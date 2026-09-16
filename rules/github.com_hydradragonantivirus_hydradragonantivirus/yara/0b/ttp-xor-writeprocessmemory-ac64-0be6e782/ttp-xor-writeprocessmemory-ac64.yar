rule TTP_XOR_WriteProcessMemory_ac64 {
  strings:
    $key_ac64 = { fb 16 [2] c9 34 [2] cf 01 [2] e1 01 [2] de 1d }

  condition:
    any of them
}