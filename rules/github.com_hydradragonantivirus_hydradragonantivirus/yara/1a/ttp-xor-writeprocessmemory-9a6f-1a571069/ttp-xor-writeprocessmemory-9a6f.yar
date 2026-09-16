rule TTP_XOR_WriteProcessMemory_9a6f {
  strings:
    $key_9a6f = { cd 1d [2] ff 3f [2] f9 0a [2] d7 0a [2] e8 16 }

  condition:
    any of them
}