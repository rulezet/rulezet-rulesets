rule TTP_XOR_WriteProcessMemory_8fc2 {
  strings:
    $key_8fc2 = { d8 b0 [2] ea 92 [2] ec a7 [2] c2 a7 [2] fd bb }

  condition:
    any of them
}