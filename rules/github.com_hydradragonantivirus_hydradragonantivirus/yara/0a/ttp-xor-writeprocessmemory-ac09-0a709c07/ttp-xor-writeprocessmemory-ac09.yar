rule TTP_XOR_WriteProcessMemory_ac09 {
  strings:
    $key_ac09 = { fb 7b [2] c9 59 [2] cf 6c [2] e1 6c [2] de 70 }

  condition:
    any of them
}