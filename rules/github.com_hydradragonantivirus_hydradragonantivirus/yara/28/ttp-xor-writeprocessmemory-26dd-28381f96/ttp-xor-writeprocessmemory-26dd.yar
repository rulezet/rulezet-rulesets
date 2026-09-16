rule TTP_XOR_WriteProcessMemory_26dd {
  strings:
    $key_26dd = { 71 af [2] 43 8d [2] 45 b8 [2] 6b b8 [2] 54 a4 }

  condition:
    any of them
}