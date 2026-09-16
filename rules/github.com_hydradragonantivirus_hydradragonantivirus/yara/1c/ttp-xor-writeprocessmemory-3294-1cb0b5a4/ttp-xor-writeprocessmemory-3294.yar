rule TTP_XOR_WriteProcessMemory_3294 {
  strings:
    $key_3294 = { 65 e6 [2] 57 c4 [2] 51 f1 [2] 7f f1 [2] 40 ed }

  condition:
    any of them
}