rule TTP_XOR_WriteProcessMemory_9ac8 {
  strings:
    $key_9ac8 = { cd ba [2] ff 98 [2] f9 ad [2] d7 ad [2] e8 b1 }

  condition:
    any of them
}