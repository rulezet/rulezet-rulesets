rule TTP_XOR_WriteProcessMemory_bd44 {
  strings:
    $key_bd44 = { ea 36 [2] d8 14 [2] de 21 [2] f0 21 [2] cf 3d }

  condition:
    any of them
}