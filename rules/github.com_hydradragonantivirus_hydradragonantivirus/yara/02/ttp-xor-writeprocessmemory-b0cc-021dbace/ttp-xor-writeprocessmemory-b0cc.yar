rule TTP_XOR_WriteProcessMemory_b0cc {
  strings:
    $key_b0cc = { e7 be [2] d5 9c [2] d3 a9 [2] fd a9 [2] c2 b5 }

  condition:
    any of them
}