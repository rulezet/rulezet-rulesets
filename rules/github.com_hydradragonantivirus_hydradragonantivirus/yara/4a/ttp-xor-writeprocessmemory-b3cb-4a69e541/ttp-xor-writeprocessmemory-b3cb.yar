rule TTP_XOR_WriteProcessMemory_b3cb {
  strings:
    $key_b3cb = { e4 b9 [2] d6 9b [2] d0 ae [2] fe ae [2] c1 b2 }

  condition:
    any of them
}