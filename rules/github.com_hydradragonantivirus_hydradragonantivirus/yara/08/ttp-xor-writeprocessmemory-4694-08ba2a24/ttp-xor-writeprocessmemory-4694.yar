rule TTP_XOR_WriteProcessMemory_4694 {
  strings:
    $key_4694 = { 11 e6 [2] 23 c4 [2] 25 f1 [2] 0b f1 [2] 34 ed }

  condition:
    any of them
}