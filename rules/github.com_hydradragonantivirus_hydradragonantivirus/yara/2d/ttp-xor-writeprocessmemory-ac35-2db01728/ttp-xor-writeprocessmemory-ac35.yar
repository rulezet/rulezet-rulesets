rule TTP_XOR_WriteProcessMemory_ac35 {
  strings:
    $key_ac35 = { fb 47 [2] c9 65 [2] cf 50 [2] e1 50 [2] de 4c }

  condition:
    any of them
}