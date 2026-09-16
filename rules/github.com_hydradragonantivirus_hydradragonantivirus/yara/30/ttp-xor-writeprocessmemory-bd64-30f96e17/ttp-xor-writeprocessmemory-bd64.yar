rule TTP_XOR_WriteProcessMemory_bd64 {
  strings:
    $key_bd64 = { ea 16 [2] d8 34 [2] de 01 [2] f0 01 [2] cf 1d }

  condition:
    any of them
}