rule TTP_XOR_WriteProcessMemory_7277 {
  strings:
    $key_7277 = { 25 05 [2] 17 27 [2] 11 12 [2] 3f 12 [2] 00 0e }

  condition:
    any of them
}