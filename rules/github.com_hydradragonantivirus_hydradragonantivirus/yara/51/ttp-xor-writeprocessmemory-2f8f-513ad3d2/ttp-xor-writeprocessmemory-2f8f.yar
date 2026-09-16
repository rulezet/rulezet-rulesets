rule TTP_XOR_WriteProcessMemory_2f8f {
  strings:
    $key_2f8f = { 78 fd [2] 4a df [2] 4c ea [2] 62 ea [2] 5d f6 }

  condition:
    any of them
}