rule TTP_XOR_WriteProcessMemory_d032 {
  strings:
    $key_d032 = { 87 40 [2] b5 62 [2] b3 57 [2] 9d 57 [2] a2 4b }

  condition:
    any of them
}