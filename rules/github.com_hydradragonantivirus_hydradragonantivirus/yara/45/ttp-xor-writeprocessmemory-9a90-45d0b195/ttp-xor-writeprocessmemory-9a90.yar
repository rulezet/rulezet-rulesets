rule TTP_XOR_WriteProcessMemory_9a90 {
  strings:
    $key_9a90 = { cd e2 [2] ff c0 [2] f9 f5 [2] d7 f5 [2] e8 e9 }

  condition:
    any of them
}