rule TTP_XOR_WriteProcessMemory_ac20 {
  strings:
    $key_ac20 = { fb 52 [2] c9 70 [2] cf 45 [2] e1 45 [2] de 59 }

  condition:
    any of them
}