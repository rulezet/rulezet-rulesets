rule TTP_XOR_WriteProcessMemory_0527 {
  strings:
    $key_0527 = { 52 55 [2] 60 77 [2] 66 42 [2] 48 42 [2] 77 5e }

  condition:
    any of them
}