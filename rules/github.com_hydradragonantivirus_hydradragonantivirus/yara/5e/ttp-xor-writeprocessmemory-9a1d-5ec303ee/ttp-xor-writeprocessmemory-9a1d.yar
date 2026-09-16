rule TTP_XOR_WriteProcessMemory_9a1d {
  strings:
    $key_9a1d = { cd 6f [2] ff 4d [2] f9 78 [2] d7 78 [2] e8 64 }

  condition:
    any of them
}