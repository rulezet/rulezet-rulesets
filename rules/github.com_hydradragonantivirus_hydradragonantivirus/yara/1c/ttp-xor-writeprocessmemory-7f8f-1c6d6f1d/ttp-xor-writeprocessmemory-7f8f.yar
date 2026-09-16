rule TTP_XOR_WriteProcessMemory_7f8f {
  strings:
    $key_7f8f = { 28 fd [2] 1a df [2] 1c ea [2] 32 ea [2] 0d f6 }

  condition:
    any of them
}