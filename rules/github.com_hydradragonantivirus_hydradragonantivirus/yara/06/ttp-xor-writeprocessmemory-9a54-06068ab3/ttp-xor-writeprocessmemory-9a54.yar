rule TTP_XOR_WriteProcessMemory_9a54 {
  strings:
    $key_9a54 = { cd 26 [2] ff 04 [2] f9 31 [2] d7 31 [2] e8 2d }

  condition:
    any of them
}