rule TTP_XOR_WriteProcessMemory_acf5 {
  strings:
    $key_acf5 = { fb 87 [2] c9 a5 [2] cf 90 [2] e1 90 [2] de 8c }

  condition:
    any of them
}