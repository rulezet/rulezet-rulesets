rule TTP_XOR_WriteProcessMemory_d107 {
  strings:
    $key_d107 = { 86 75 [2] b4 57 [2] b2 62 [2] 9c 62 [2] a3 7e }

  condition:
    any of them
}