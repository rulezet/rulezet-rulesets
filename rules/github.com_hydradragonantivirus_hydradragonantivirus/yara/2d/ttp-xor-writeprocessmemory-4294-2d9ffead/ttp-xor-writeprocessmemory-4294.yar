rule TTP_XOR_WriteProcessMemory_4294 {
  strings:
    $key_4294 = { 15 e6 [2] 27 c4 [2] 21 f1 [2] 0f f1 [2] 30 ed }

  condition:
    any of them
}