rule TTP_XOR_WriteProcessMemory_b4cb {
  strings:
    $key_b4cb = { e3 b9 [2] d1 9b [2] d7 ae [2] f9 ae [2] c6 b2 }

  condition:
    any of them
}