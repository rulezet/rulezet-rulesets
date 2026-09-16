rule TTP_XOR_WriteProcessMemory_acf7 {
  strings:
    $key_acf7 = { fb 85 [2] c9 a7 [2] cf 92 [2] e1 92 [2] de 8e }

  condition:
    any of them
}