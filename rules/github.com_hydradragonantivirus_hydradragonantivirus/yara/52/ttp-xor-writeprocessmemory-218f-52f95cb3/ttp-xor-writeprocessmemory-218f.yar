rule TTP_XOR_WriteProcessMemory_218f {
  strings:
    $key_218f = { 76 fd [2] 44 df [2] 42 ea [2] 6c ea [2] 53 f6 }

  condition:
    any of them
}