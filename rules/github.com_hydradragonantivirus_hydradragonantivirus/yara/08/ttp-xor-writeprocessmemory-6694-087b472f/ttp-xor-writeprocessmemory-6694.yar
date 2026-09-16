rule TTP_XOR_WriteProcessMemory_6694 {
  strings:
    $key_6694 = { 31 e6 [2] 03 c4 [2] 05 f1 [2] 2b f1 [2] 14 ed }

  condition:
    any of them
}