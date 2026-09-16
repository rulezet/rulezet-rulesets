rule TTP_XOR_WriteProcessMemory_9a6d {
  strings:
    $key_9a6d = { cd 1f [2] ff 3d [2] f9 08 [2] d7 08 [2] e8 14 }

  condition:
    any of them
}