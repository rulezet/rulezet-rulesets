rule TTP_XOR_WriteProcessMemory_9a85 {
  strings:
    $key_9a85 = { cd f7 [2] ff d5 [2] f9 e0 [2] d7 e0 [2] e8 fc }

  condition:
    any of them
}