rule TTP_XOR_WriteProcessMemory_9aa6 {
  strings:
    $key_9aa6 = { cd d4 [2] ff f6 [2] f9 c3 [2] d7 c3 [2] e8 df }

  condition:
    any of them
}