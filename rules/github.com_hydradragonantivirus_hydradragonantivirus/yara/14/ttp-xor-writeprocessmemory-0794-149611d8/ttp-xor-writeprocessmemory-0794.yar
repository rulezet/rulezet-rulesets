rule TTP_XOR_WriteProcessMemory_0794 {
  strings:
    $key_0794 = { 50 e6 [2] 62 c4 [2] 64 f1 [2] 4a f1 [2] 75 ed }

  condition:
    any of them
}