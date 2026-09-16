rule TTP_XOR_WriteProcessMemory_ac59 {
  strings:
    $key_ac59 = { fb 2b [2] c9 09 [2] cf 3c [2] e1 3c [2] de 20 }

  condition:
    any of them
}