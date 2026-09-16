rule TTP_XOR_WriteProcessMemory_9a27 {
  strings:
    $key_9a27 = { cd 55 [2] ff 77 [2] f9 42 [2] d7 42 [2] e8 5e }

  condition:
    any of them
}