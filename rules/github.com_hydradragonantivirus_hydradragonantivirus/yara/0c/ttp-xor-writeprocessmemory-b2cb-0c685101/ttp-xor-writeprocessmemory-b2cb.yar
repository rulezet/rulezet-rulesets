rule TTP_XOR_WriteProcessMemory_b2cb {
  strings:
    $key_b2cb = { e5 b9 [2] d7 9b [2] d1 ae [2] ff ae [2] c0 b2 }

  condition:
    any of them
}