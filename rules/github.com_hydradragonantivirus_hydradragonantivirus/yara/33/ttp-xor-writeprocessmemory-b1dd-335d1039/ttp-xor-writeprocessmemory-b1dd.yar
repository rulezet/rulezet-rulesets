rule TTP_XOR_WriteProcessMemory_b1dd {
  strings:
    $key_b1dd = { e6 af [2] d4 8d [2] d2 b8 [2] fc b8 [2] c3 a4 }

  condition:
    any of them
}