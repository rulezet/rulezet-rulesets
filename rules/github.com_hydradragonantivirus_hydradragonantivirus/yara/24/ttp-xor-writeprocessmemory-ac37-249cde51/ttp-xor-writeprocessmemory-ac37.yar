rule TTP_XOR_WriteProcessMemory_ac37 {
  strings:
    $key_ac37 = { fb 45 [2] c9 67 [2] cf 52 [2] e1 52 [2] de 4e }

  condition:
    any of them
}