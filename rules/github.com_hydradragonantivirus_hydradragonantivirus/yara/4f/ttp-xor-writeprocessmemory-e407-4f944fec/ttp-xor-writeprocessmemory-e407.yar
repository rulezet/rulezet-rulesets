rule TTP_XOR_WriteProcessMemory_e407 {
  strings:
    $key_e407 = { b3 75 [2] 81 57 [2] 87 62 [2] a9 62 [2] 96 7e }

  condition:
    any of them
}