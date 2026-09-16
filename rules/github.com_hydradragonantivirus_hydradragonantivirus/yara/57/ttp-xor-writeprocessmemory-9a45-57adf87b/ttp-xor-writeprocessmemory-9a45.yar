rule TTP_XOR_WriteProcessMemory_9a45 {
  strings:
    $key_9a45 = { cd 37 [2] ff 15 [2] f9 20 [2] d7 20 [2] e8 3c }

  condition:
    any of them
}