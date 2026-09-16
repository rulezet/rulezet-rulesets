rule TTP_XOR_WriteProcessMemory_f394 {
  strings:
    $key_f394 = { a4 e6 [2] 96 c4 [2] 90 f1 [2] be f1 [2] 81 ed }

  condition:
    any of them
}