rule TTP_XOR_WriteProcessMemory_9a6a {
  strings:
    $key_9a6a = { cd 18 [2] ff 3a [2] f9 0f [2] d7 0f [2] e8 13 }

  condition:
    any of them
}