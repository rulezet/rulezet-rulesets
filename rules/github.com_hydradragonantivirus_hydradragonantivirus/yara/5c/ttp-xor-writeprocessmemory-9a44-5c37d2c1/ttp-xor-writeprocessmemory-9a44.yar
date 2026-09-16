rule TTP_XOR_WriteProcessMemory_9a44 {
  strings:
    $key_9a44 = { cd 36 [2] ff 14 [2] f9 21 [2] d7 21 [2] e8 3d }

  condition:
    any of them
}