rule TTP_XOR_WriteProcessMemory_9a2d {
  strings:
    $key_9a2d = { cd 5f [2] ff 7d [2] f9 48 [2] d7 48 [2] e8 54 }

  condition:
    any of them
}