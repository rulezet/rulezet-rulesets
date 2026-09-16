rule TTP_XOR_WriteProcessMemory_ac29 {
  strings:
    $key_ac29 = { fb 5b [2] c9 79 [2] cf 4c [2] e1 4c [2] de 50 }

  condition:
    any of them
}