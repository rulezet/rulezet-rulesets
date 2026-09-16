rule TTP_XOR_WriteProcessMemory_ac73 {
  strings:
    $key_ac73 = { fb 01 [2] c9 23 [2] cf 16 [2] e1 16 [2] de 0a }

  condition:
    any of them
}