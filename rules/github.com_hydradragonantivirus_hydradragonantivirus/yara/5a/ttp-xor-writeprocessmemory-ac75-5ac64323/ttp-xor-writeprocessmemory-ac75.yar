rule TTP_XOR_WriteProcessMemory_ac75 {
  strings:
    $key_ac75 = { fb 07 [2] c9 25 [2] cf 10 [2] e1 10 [2] de 0c }

  condition:
    any of them
}