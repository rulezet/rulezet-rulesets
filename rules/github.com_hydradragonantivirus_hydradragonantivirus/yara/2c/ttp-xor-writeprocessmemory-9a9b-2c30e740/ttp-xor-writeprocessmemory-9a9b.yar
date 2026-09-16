rule TTP_XOR_WriteProcessMemory_9a9b {
  strings:
    $key_9a9b = { cd e9 [2] ff cb [2] f9 fe [2] d7 fe [2] e8 e2 }

  condition:
    any of them
}