rule TTP_XOR_WriteProcessMemory_0543 {
  strings:
    $key_0543 = { 52 31 [2] 60 13 [2] 66 26 [2] 48 26 [2] 77 3a }

  condition:
    any of them
}