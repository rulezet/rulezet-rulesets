rule TTP_XOR_WriteProcessMemory_4f8f {
  strings:
    $key_4f8f = { 18 fd [2] 2a df [2] 2c ea [2] 02 ea [2] 3d f6 }

  condition:
    any of them
}