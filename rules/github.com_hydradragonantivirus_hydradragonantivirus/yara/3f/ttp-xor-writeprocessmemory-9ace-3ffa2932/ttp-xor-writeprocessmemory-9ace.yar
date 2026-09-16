rule TTP_XOR_WriteProcessMemory_9ace {
  strings:
    $key_9ace = { cd bc [2] ff 9e [2] f9 ab [2] d7 ab [2] e8 b7 }

  condition:
    any of them
}