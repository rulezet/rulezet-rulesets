rule TTP_XOR_WriteProcessMemory_0563 {
  strings:
    $key_0563 = { 52 11 [2] 60 33 [2] 66 06 [2] 48 06 [2] 77 1a }

  condition:
    any of them
}