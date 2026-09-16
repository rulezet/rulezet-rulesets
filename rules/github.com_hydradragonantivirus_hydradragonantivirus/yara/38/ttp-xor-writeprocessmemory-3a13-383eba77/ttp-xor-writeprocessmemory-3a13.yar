rule TTP_XOR_WriteProcessMemory_3a13 {
  strings:
    $key_3a13 = { 6d 61 [2] 5f 43 [2] 59 76 [2] 77 76 [2] 48 6a }

  condition:
    any of them
}