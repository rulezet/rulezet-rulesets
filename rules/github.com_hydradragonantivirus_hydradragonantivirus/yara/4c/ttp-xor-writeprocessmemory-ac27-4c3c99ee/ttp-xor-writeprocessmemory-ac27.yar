rule TTP_XOR_WriteProcessMemory_ac27 {
  strings:
    $key_ac27 = { fb 55 [2] c9 77 [2] cf 42 [2] e1 42 [2] de 5e }

  condition:
    any of them
}