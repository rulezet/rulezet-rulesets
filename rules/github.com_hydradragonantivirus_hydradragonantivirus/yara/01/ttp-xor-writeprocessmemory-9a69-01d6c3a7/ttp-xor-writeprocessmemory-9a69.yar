rule TTP_XOR_WriteProcessMemory_9a69 {
  strings:
    $key_9a69 = { cd 1b [2] ff 39 [2] f9 0c [2] d7 0c [2] e8 10 }

  condition:
    any of them
}