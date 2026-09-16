rule TTP_XOR_WriteProcessMemory_9a15 {
  strings:
    $key_9a15 = { cd 67 [2] ff 45 [2] f9 70 [2] d7 70 [2] e8 6c }

  condition:
    any of them
}