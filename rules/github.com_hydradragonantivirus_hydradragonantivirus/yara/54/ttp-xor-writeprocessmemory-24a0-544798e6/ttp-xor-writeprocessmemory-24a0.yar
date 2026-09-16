rule TTP_XOR_WriteProcessMemory_24a0 {
  strings:
    $key_24a0 = { 73 d2 [2] 41 f0 [2] 47 c5 [2] 69 c5 [2] 56 d9 }

  condition:
    any of them
}