rule TTP_XOR_WriteProcessMemory_9a48 {
  strings:
    $key_9a48 = { cd 3a [2] ff 18 [2] f9 2d [2] d7 2d [2] e8 31 }

  condition:
    any of them
}