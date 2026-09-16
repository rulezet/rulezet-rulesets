rule TTP_XOR_WriteProcessMemory_9ac2 {
  strings:
    $key_9ac2 = { cd b0 [2] ff 92 [2] f9 a7 [2] d7 a7 [2] e8 bb }

  condition:
    any of them
}