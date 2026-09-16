rule TTP_XOR_WriteProcessMemory_7c80 {
  strings:
    $key_7c80 = { 2b f2 [2] 19 d0 [2] 1f e5 [2] 31 e5 [2] 0e f9 }

  condition:
    any of them
}