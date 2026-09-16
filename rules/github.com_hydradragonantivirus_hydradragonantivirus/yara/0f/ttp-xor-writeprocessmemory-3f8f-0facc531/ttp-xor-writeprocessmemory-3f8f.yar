rule TTP_XOR_WriteProcessMemory_3f8f {
  strings:
    $key_3f8f = { 68 fd [2] 5a df [2] 5c ea [2] 72 ea [2] 4d f6 }

  condition:
    any of them
}