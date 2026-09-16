rule TTP_XOR_WriteProcessMemory_a6a8 {
  strings:
    $key_a6a8 = { f1 da [2] c3 f8 [2] c5 cd [2] eb cd [2] d4 d1 }

  condition:
    any of them
}