rule TTP_XOR_WriteProcessMemory_3694 {
  strings:
    $key_3694 = { 61 e6 [2] 53 c4 [2] 55 f1 [2] 7b f1 [2] 44 ed }

  condition:
    any of them
}