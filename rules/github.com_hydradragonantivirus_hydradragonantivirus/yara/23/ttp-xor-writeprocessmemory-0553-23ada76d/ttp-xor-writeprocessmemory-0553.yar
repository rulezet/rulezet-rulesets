rule TTP_XOR_WriteProcessMemory_0553 {
  strings:
    $key_0553 = { 52 21 [2] 60 03 [2] 66 36 [2] 48 36 [2] 77 2a }

  condition:
    any of them
}