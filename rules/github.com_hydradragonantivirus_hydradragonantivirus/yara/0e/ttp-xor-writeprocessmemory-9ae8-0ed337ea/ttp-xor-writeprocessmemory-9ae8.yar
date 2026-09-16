rule TTP_XOR_WriteProcessMemory_9ae8 {
  strings:
    $key_9ae8 = { cd 9a [2] ff b8 [2] f9 8d [2] d7 8d [2] e8 91 }

  condition:
    any of them
}