rule TTP_XOR_WriteProcessMemory_9a11 {
  strings:
    $key_9a11 = { cd 63 [2] ff 41 [2] f9 74 [2] d7 74 [2] e8 68 }

  condition:
    any of them
}