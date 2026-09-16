rule TTP_XOR_WriteProcessMemory_9aa1 {
  strings:
    $key_9aa1 = { cd d3 [2] ff f1 [2] f9 c4 [2] d7 c4 [2] e8 d8 }

  condition:
    any of them
}