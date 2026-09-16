rule TTP_XOR_WriteProcessMemory_9add {
  strings:
    $key_9add = { cd af [2] ff 8d [2] f9 b8 [2] d7 b8 [2] e8 a4 }

  condition:
    any of them
}