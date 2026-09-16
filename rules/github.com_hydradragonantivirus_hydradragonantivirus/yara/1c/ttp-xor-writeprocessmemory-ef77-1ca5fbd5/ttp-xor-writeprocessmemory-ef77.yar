rule TTP_XOR_WriteProcessMemory_ef77 {
  strings:
    $key_ef77 = { b8 05 [2] 8a 27 [2] 8c 12 [2] a2 12 [2] 9d 0e }

  condition:
    any of them
}