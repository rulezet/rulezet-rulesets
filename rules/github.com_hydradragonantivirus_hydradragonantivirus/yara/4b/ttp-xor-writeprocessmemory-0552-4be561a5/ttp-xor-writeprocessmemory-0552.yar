rule TTP_XOR_WriteProcessMemory_0552 {
  strings:
    $key_0552 = { 52 20 [2] 60 02 [2] 66 37 [2] 48 37 [2] 77 2b }

  condition:
    any of them
}