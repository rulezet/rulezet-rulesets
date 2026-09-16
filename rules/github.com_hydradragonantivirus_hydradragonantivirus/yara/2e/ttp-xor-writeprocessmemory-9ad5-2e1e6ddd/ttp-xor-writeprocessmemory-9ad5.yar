rule TTP_XOR_WriteProcessMemory_9ad5 {
  strings:
    $key_9ad5 = { cd a7 [2] ff 85 [2] f9 b0 [2] d7 b0 [2] e8 ac }

  condition:
    any of them
}