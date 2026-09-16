rule TTP_XOR_WriteProcessMemory_0522 {
  strings:
    $key_0522 = { 52 50 [2] 60 72 [2] 66 47 [2] 48 47 [2] 77 5b }

  condition:
    any of them
}