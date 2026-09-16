rule TTP_XOR_WriteProcessMemory_0541 {
  strings:
    $key_0541 = { 52 33 [2] 60 11 [2] 66 24 [2] 48 24 [2] 77 38 }

  condition:
    any of them
}