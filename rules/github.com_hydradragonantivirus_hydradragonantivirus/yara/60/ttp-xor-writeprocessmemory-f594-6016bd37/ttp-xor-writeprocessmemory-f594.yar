rule TTP_XOR_WriteProcessMemory_f594 {
  strings:
    $key_f594 = { a2 e6 [2] 90 c4 [2] 96 f1 [2] b8 f1 [2] 87 ed }

  condition:
    any of them
}