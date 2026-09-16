rule TTP_XOR_WriteProcessMemory_bd8b {
  strings:
    $key_bd8b = { ea f9 [2] d8 db [2] de ee [2] f0 ee [2] cf f2 }

  condition:
    any of them
}