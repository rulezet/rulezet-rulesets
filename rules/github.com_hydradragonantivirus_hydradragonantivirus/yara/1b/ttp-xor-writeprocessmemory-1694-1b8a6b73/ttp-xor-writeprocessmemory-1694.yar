rule TTP_XOR_WriteProcessMemory_1694 {
  strings:
    $key_1694 = { 41 e6 [2] 73 c4 [2] 75 f1 [2] 5b f1 [2] 64 ed }

  condition:
    any of them
}