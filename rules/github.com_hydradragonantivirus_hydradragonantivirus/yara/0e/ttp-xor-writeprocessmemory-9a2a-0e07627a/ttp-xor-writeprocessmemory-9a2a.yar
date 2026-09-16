rule TTP_XOR_WriteProcessMemory_9a2a {
  strings:
    $key_9a2a = { cd 58 [2] ff 7a [2] f9 4f [2] d7 4f [2] e8 53 }

  condition:
    any of them
}