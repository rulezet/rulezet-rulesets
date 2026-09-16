rule TTP_XOR_WriteProcessMemory_ac34 {
  strings:
    $key_ac34 = { fb 46 [2] c9 64 [2] cf 51 [2] e1 51 [2] de 4d }

  condition:
    any of them
}