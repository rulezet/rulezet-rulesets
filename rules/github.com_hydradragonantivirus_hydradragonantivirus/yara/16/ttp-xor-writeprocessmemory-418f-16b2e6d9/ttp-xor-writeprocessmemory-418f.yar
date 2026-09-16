rule TTP_XOR_WriteProcessMemory_418f {
  strings:
    $key_418f = { 16 fd [2] 24 df [2] 22 ea [2] 0c ea [2] 33 f6 }

  condition:
    any of them
}