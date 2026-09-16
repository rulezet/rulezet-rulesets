rule TTP_XOR_WriteProcessMemory_9a31 {
  strings:
    $key_9a31 = { cd 43 [2] ff 61 [2] f9 54 [2] d7 54 [2] e8 48 }

  condition:
    any of them
}