rule TTP_XOR_WriteProcessMemory_9a95 {
  strings:
    $key_9a95 = { cd e7 [2] ff c5 [2] f9 f0 [2] d7 f0 [2] e8 ec }

  condition:
    any of them
}