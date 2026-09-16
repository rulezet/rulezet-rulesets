rule TTP_XOR_WriteProcessMemory_ac08 {
  strings:
    $key_ac08 = { fb 7a [2] c9 58 [2] cf 6d [2] e1 6d [2] de 71 }

  condition:
    any of them
}