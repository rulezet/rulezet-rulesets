rule TTP_XOR_WriteProcessMemory_9a77 {
  strings:
    $key_9a77 = { cd 05 [2] ff 27 [2] f9 12 [2] d7 12 [2] e8 0e }

  condition:
    any of them
}