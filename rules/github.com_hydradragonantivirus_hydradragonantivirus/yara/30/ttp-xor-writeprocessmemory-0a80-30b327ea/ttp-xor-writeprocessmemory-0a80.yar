rule TTP_XOR_WriteProcessMemory_0a80 {
  strings:
    $key_0a80 = { 5d f2 [2] 6f d0 [2] 69 e5 [2] 47 e5 [2] 78 f9 }

  condition:
    any of them
}