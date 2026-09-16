rule TTP_XOR_WriteProcessMemory_8327 {
  strings:
    $key_8327 = { d4 55 [2] e6 77 [2] e0 42 [2] ce 42 [2] f1 5e }

  condition:
    any of them
}