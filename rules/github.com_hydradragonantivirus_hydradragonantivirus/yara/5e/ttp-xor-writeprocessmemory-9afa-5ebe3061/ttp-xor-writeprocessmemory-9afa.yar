rule TTP_XOR_WriteProcessMemory_9afa {
  strings:
    $key_9afa = { cd 88 [2] ff aa [2] f9 9f [2] d7 9f [2] e8 83 }

  condition:
    any of them
}