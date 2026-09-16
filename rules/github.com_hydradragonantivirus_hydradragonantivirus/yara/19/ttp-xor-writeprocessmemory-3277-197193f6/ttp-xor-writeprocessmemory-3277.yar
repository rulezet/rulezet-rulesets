rule TTP_XOR_WriteProcessMemory_3277 {
  strings:
    $key_3277 = { 65 05 [2] 57 27 [2] 51 12 [2] 7f 12 [2] 40 0e }

  condition:
    any of them
}