rule TTP_XOR_WriteProcessMemory_2033 {
  strings:
    $key_2033 = { 77 41 [2] 45 63 [2] 43 56 [2] 6d 56 [2] 52 4a }

  condition:
    any of them
}