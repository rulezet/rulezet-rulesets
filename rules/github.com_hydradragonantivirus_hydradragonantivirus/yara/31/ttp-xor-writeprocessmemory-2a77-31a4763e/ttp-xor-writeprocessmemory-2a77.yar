rule TTP_XOR_WriteProcessMemory_2a77 {
  strings:
    $key_2a77 = { 7d 05 [2] 4f 27 [2] 49 12 [2] 67 12 [2] 58 0e }

  condition:
    any of them
}