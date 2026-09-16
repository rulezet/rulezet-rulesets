rule TTP_XOR_WriteProcessMemory_9aea {
  strings:
    $key_9aea = { cd 98 [2] ff ba [2] f9 8f [2] d7 8f [2] e8 93 }

  condition:
    any of them
}