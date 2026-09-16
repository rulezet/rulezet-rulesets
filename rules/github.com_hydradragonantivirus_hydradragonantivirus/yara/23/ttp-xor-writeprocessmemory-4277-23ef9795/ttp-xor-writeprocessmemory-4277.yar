rule TTP_XOR_WriteProcessMemory_4277 {
  strings:
    $key_4277 = { 15 05 [2] 27 27 [2] 21 12 [2] 0f 12 [2] 30 0e }

  condition:
    any of them
}