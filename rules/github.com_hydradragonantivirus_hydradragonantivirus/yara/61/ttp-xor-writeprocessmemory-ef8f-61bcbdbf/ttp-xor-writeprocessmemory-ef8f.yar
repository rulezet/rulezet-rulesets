rule TTP_XOR_WriteProcessMemory_ef8f {
  strings:
    $key_ef8f = { b8 fd [2] 8a df [2] 8c ea [2] a2 ea [2] 9d f6 }

  condition:
    any of them
}