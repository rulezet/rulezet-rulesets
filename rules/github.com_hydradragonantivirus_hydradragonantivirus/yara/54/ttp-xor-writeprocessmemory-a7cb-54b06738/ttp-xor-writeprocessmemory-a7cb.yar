rule TTP_XOR_WriteProcessMemory_a7cb {
  strings:
    $key_a7cb = { f0 b9 [2] c2 9b [2] c4 ae [2] ea ae [2] d5 b2 }

  condition:
    any of them
}