rule TTP_XOR_WriteProcessMemory_ac03 {
  strings:
    $key_ac03 = { fb 71 [2] c9 53 [2] cf 66 [2] e1 66 [2] de 7a }

  condition:
    any of them
}