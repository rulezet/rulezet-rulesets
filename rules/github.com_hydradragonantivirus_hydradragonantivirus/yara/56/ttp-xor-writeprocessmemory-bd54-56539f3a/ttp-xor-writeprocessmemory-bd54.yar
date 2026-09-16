rule TTP_XOR_WriteProcessMemory_bd54 {
  strings:
    $key_bd54 = { ea 26 [2] d8 04 [2] de 31 [2] f0 31 [2] cf 2d }

  condition:
    any of them
}