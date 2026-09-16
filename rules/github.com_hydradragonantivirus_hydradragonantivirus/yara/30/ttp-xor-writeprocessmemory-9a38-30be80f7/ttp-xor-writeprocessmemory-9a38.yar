rule TTP_XOR_WriteProcessMemory_9a38 {
  strings:
    $key_9a38 = { cd 4a [2] ff 68 [2] f9 5d [2] d7 5d [2] e8 41 }

  condition:
    any of them
}