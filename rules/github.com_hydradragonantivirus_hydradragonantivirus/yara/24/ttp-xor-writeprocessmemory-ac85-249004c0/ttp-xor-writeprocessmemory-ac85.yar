rule TTP_XOR_WriteProcessMemory_ac85 {
  strings:
    $key_ac85 = { fb f7 [2] c9 d5 [2] cf e0 [2] e1 e0 [2] de fc }

  condition:
    any of them
}