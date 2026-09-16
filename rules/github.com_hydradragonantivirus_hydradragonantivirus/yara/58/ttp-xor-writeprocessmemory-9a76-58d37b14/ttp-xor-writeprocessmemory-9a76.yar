rule TTP_XOR_WriteProcessMemory_9a76 {
  strings:
    $key_9a76 = { cd 04 [2] ff 26 [2] f9 13 [2] d7 13 [2] e8 0f }

  condition:
    any of them
}