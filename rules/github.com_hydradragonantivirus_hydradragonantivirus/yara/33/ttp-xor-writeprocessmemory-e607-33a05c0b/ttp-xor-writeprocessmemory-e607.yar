rule TTP_XOR_WriteProcessMemory_e607 {
  strings:
    $key_e607 = { b1 75 [2] 83 57 [2] 85 62 [2] ab 62 [2] 94 7e }

  condition:
    any of them
}