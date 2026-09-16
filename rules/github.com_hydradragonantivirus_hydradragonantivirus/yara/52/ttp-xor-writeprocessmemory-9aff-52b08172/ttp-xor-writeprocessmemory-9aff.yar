rule TTP_XOR_WriteProcessMemory_9aff {
  strings:
    $key_9aff = { cd 8d [2] ff af [2] f9 9a [2] d7 9a [2] e8 86 }

  condition:
    any of them
}