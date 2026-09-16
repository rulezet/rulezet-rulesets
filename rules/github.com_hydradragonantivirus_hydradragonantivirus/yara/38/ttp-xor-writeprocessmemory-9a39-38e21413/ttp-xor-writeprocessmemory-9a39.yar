rule TTP_XOR_WriteProcessMemory_9a39 {
  strings:
    $key_9a39 = { cd 4b [2] ff 69 [2] f9 5c [2] d7 5c [2] e8 40 }

  condition:
    any of them
}