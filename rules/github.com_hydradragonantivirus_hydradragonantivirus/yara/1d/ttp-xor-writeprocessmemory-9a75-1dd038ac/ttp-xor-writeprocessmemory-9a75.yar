rule TTP_XOR_WriteProcessMemory_9a75 {
  strings:
    $key_9a75 = { cd 07 [2] ff 25 [2] f9 10 [2] d7 10 [2] e8 0c }

  condition:
    any of them
}