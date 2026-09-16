rule TTP_XOR_WriteProcessMemory_a0ce {
  strings:
    $key_a0ce = { f7 bc [2] c5 9e [2] c3 ab [2] ed ab [2] d2 b7 }

  condition:
    any of them
}