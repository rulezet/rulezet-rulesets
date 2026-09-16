rule TTP_XOR_WriteProcessMemory_4250 {
  strings:
    $key_4250 = { 15 22 [2] 27 00 [2] 21 35 [2] 0f 35 [2] 30 29 }

  condition:
    any of them
}