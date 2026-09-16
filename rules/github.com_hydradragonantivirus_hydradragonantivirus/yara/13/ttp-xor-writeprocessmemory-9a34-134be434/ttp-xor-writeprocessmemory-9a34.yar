rule TTP_XOR_WriteProcessMemory_9a34 {
  strings:
    $key_9a34 = { cd 46 [2] ff 64 [2] f9 51 [2] d7 51 [2] e8 4d }

  condition:
    any of them
}