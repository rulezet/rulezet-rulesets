rule TTP_XOR_WriteProcessMemory_9a86 {
  strings:
    $key_9a86 = { cd f4 [2] ff d6 [2] f9 e3 [2] d7 e3 [2] e8 ff }

  condition:
    any of them
}