rule TTP_XOR_WriteProcessMemory_9a96 {
  strings:
    $key_9a96 = { cd e4 [2] ff c6 [2] f9 f3 [2] d7 f3 [2] e8 ef }

  condition:
    any of them
}