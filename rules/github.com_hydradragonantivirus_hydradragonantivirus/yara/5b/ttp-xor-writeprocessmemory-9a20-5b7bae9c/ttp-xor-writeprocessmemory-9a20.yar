rule TTP_XOR_WriteProcessMemory_9a20 {
  strings:
    $key_9a20 = { cd 52 [2] ff 70 [2] f9 45 [2] d7 45 [2] e8 59 }

  condition:
    any of them
}