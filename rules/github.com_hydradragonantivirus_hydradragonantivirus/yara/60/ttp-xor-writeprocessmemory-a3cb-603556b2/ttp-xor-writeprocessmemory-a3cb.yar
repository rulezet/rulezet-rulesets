rule TTP_XOR_WriteProcessMemory_a3cb {
  strings:
    $key_a3cb = { f4 b9 [2] c6 9b [2] c0 ae [2] ee ae [2] d1 b2 }

  condition:
    any of them
}