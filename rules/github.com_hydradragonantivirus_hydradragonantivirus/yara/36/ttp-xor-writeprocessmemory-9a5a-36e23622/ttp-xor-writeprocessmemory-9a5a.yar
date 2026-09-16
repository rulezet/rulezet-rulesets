rule TTP_XOR_WriteProcessMemory_9a5a {
  strings:
    $key_9a5a = { cd 28 [2] ff 0a [2] f9 3f [2] d7 3f [2] e8 23 }

  condition:
    any of them
}