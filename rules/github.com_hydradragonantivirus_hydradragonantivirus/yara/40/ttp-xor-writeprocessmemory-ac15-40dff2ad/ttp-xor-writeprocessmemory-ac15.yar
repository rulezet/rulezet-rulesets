rule TTP_XOR_WriteProcessMemory_ac15 {
  strings:
    $key_ac15 = { fb 67 [2] c9 45 [2] cf 70 [2] e1 70 [2] de 6c }

  condition:
    any of them
}