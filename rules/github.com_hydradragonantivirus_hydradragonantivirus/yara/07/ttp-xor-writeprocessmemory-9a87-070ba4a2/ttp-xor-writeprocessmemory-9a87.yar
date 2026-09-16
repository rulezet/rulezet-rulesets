rule TTP_XOR_WriteProcessMemory_9a87 {
  strings:
    $key_9a87 = { cd f5 [2] ff d7 [2] f9 e2 [2] d7 e2 [2] e8 fe }

  condition:
    any of them
}