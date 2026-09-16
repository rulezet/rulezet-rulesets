rule TTP_XOR_WriteProcessMemory_ac14 {
  strings:
    $key_ac14 = { fb 66 [2] c9 44 [2] cf 71 [2] e1 71 [2] de 6d }

  condition:
    any of them
}