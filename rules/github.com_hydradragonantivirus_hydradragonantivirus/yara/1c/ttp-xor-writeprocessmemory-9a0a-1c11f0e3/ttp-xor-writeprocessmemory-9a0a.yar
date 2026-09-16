rule TTP_XOR_WriteProcessMemory_9a0a {
  strings:
    $key_9a0a = { cd 78 [2] ff 5a [2] f9 6f [2] d7 6f [2] e8 73 }

  condition:
    any of them
}