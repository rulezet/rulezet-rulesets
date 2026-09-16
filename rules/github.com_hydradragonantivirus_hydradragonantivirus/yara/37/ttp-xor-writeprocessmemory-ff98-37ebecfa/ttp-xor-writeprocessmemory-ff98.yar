rule TTP_XOR_WriteProcessMemory_ff98 {
  strings:
    $key_ff98 = { a8 ea [2] 9a c8 [2] 9c fd [2] b2 fd [2] 8d e1 }

  condition:
    any of them
}