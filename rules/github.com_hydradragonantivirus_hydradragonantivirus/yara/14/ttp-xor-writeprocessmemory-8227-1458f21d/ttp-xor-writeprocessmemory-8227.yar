rule TTP_XOR_WriteProcessMemory_8227 {
  strings:
    $key_8227 = { d5 55 [2] e7 77 [2] e1 42 [2] cf 42 [2] f0 5e }

  condition:
    any of them
}