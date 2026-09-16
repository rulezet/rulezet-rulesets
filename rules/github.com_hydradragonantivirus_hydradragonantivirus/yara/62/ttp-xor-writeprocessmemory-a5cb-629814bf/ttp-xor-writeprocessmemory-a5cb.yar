rule TTP_XOR_WriteProcessMemory_a5cb {
  strings:
    $key_a5cb = { f2 b9 [2] c0 9b [2] c6 ae [2] e8 ae [2] d7 b2 }

  condition:
    any of them
}