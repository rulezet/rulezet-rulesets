rule TTP_XOR_WriteProcessMemory_0550 {
  strings:
    $key_0550 = { 52 22 [2] 60 00 [2] 66 35 [2] 48 35 [2] 77 29 }

  condition:
    any of them
}