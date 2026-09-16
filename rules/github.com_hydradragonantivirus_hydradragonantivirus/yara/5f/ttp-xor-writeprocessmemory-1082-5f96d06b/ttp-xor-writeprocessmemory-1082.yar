rule TTP_XOR_WriteProcessMemory_1082 {
  strings:
    $key_1082 = { 47 f0 [2] 75 d2 [2] 73 e7 [2] 5d e7 [2] 62 fb }

  condition:
    any of them
}