rule TTP_XOR_WriteProcessMemory_bd24 {
  strings:
    $key_bd24 = { ea 56 [2] d8 74 [2] de 41 [2] f0 41 [2] cf 5d }

  condition:
    any of them
}