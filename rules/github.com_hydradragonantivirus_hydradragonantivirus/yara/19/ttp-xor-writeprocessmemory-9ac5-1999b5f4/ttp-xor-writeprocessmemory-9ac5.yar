rule TTP_XOR_WriteProcessMemory_9ac5 {
  strings:
    $key_9ac5 = { cd b7 [2] ff 95 [2] f9 a0 [2] d7 a0 [2] e8 bc }

  condition:
    any of them
}