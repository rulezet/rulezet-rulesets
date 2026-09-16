rule TTP_XOR_WriteProcessMemory_268f {
  strings:
    $key_268f = { 71 fd [2] 43 df [2] 45 ea [2] 6b ea [2] 54 f6 }

  condition:
    any of them
}