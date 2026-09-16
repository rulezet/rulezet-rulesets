rule TTP_XOR_WriteProcessMemory_9295 {
  strings:
    $key_9295 = { c5 e7 [2] f7 c5 [2] f1 f0 [2] df f0 [2] e0 ec }

  condition:
    any of them
}