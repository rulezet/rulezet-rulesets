rule TTP_XOR_WriteProcessMemory_f494 {
  strings:
    $key_f494 = { a3 e6 [2] 91 c4 [2] 97 f1 [2] b9 f1 [2] 86 ed }

  condition:
    any of them
}