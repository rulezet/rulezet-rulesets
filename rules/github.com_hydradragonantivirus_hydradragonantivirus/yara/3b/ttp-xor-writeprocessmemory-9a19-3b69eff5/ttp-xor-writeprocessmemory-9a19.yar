rule TTP_XOR_WriteProcessMemory_9a19 {
  strings:
    $key_9a19 = { cd 6b [2] ff 49 [2] f9 7c [2] d7 7c [2] e8 60 }

  condition:
    any of them
}