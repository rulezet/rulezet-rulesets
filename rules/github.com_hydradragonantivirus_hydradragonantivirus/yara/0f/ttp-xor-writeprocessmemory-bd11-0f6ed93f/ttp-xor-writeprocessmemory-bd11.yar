rule TTP_XOR_WriteProcessMemory_bd11 {
  strings:
    $key_bd11 = { ea 63 [2] d8 41 [2] de 74 [2] f0 74 [2] cf 68 }

  condition:
    any of them
}