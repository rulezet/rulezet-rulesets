rule TTP_XOR_WriteProcessMemory_9a3d {
  strings:
    $key_9a3d = { cd 4f [2] ff 6d [2] f9 58 [2] d7 58 [2] e8 44 }

  condition:
    any of them
}