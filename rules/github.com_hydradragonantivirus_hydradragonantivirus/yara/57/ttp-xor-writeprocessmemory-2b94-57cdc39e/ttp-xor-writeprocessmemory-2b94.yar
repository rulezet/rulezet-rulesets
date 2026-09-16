rule TTP_XOR_WriteProcessMemory_2b94 {
  strings:
    $key_2b94 = { 7c e6 [2] 4e c4 [2] 48 f1 [2] 66 f1 [2] 59 ed }

  condition:
    any of them
}