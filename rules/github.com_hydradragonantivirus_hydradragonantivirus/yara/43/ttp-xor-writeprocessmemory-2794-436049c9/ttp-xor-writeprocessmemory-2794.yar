rule TTP_XOR_WriteProcessMemory_2794 {
  strings:
    $key_2794 = { 70 e6 [2] 42 c4 [2] 44 f1 [2] 6a f1 [2] 55 ed }

  condition:
    any of them
}