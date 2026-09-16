rule TTP_XOR_WriteProcessMemory_1093 {
  strings:
    $key_1093 = { 47 e1 [2] 75 c3 [2] 73 f6 [2] 5d f6 [2] 62 ea }

  condition:
    any of them
}