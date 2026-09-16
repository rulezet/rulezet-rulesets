rule TTP_XOR_WriteProcessMemory_9aa7 {
  strings:
    $key_9aa7 = { cd d5 [2] ff f7 [2] f9 c2 [2] d7 c2 [2] e8 de }

  condition:
    any of them
}