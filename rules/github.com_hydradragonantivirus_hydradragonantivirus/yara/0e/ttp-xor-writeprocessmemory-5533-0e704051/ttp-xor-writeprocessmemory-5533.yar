rule TTP_XOR_WriteProcessMemory_5533 {
  strings:
    $key_5533 = { 02 41 [2] 30 63 [2] 36 56 [2] 18 56 [2] 27 4a }

  condition:
    any of them
}