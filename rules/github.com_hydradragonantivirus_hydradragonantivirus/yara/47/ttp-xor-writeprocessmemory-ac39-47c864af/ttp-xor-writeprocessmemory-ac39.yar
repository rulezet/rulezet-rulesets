rule TTP_XOR_WriteProcessMemory_ac39 {
  strings:
    $key_ac39 = { fb 4b [2] c9 69 [2] cf 5c [2] e1 5c [2] de 40 }

  condition:
    any of them
}