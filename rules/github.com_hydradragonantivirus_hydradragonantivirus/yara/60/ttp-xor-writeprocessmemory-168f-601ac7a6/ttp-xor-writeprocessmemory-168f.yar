rule TTP_XOR_WriteProcessMemory_168f {
  strings:
    $key_168f = { 41 fd [2] 73 df [2] 75 ea [2] 5b ea [2] 64 f6 }

  condition:
    any of them
}