rule TTP_XOR_WriteProcessMemory_a0a8 {
  strings:
    $key_a0a8 = { f7 da [2] c5 f8 [2] c3 cd [2] ed cd [2] d2 d1 }

  condition:
    any of them
}