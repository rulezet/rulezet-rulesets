rule TTP_XOR_WriteProcessMemory_9a7f {
  strings:
    $key_9a7f = { cd 0d [2] ff 2f [2] f9 1a [2] d7 1a [2] e8 06 }

  condition:
    any of them
}