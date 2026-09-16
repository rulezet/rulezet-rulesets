rule TTP_XOR_WriteProcessMemory_2856 {
  strings:
    $key_2856 = { 7f 24 [2] 4d 06 [2] 4b 33 [2] 65 33 [2] 5a 2f }

  condition:
    any of them
}