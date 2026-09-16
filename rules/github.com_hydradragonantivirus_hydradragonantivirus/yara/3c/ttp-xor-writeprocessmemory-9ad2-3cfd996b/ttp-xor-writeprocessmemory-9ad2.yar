rule TTP_XOR_WriteProcessMemory_9ad2 {
  strings:
    $key_9ad2 = { cd a0 [2] ff 82 [2] f9 b7 [2] d7 b7 [2] e8 ab }

  condition:
    any of them
}