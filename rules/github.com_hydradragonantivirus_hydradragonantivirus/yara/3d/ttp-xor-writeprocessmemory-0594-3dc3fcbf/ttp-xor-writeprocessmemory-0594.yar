rule TTP_XOR_WriteProcessMemory_0594 {
  strings:
    $key_0594 = { 52 e6 [2] 60 c4 [2] 66 f1 [2] 48 f1 [2] 77 ed }

  condition:
    any of them
}