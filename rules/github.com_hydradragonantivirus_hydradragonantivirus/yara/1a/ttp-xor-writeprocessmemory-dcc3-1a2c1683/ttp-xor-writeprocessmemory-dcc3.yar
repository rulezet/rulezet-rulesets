rule TTP_XOR_WriteProcessMemory_dcc3 {
  strings:
    $key_dcc3 = { 8b b1 [2] b9 93 [2] bf a6 [2] 91 a6 [2] ae ba }

  condition:
    any of them
}