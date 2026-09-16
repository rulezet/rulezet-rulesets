rule TTP_XOR_WriteProcessMemory_9a13 {
  strings:
    $key_9a13 = { cd 61 [2] ff 43 [2] f9 76 [2] d7 76 [2] e8 6a }

  condition:
    any of them
}