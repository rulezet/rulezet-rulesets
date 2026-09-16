rule TTP_XOR_WriteProcessMemory_b5cb {
  strings:
    $key_b5cb = { e2 b9 [2] d0 9b [2] d6 ae [2] f8 ae [2] c7 b2 }

  condition:
    any of them
}