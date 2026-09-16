rule TTP_XOR_WriteProcessMemory_9a1f {
  strings:
    $key_9a1f = { cd 6d [2] ff 4f [2] f9 7a [2] d7 7a [2] e8 66 }

  condition:
    any of them
}