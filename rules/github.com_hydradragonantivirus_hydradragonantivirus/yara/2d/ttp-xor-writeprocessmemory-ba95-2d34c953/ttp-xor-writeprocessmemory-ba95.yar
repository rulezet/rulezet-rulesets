rule TTP_XOR_WriteProcessMemory_ba95 {
  strings:
    $key_ba95 = { ed e7 [2] df c5 [2] d9 f0 [2] f7 f0 [2] c8 ec }

  condition:
    any of them
}