rule TTP_XOR_WriteProcessMemory_0e11 {
  strings:
    $key_0e11 = { 59 63 [2] 6b 41 [2] 6d 74 [2] 43 74 [2] 7c 68 }

  condition:
    any of them
}