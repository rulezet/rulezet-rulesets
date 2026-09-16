rule TTP_XOR_WriteProcessMemory_ff8f {
  strings:
    $key_ff8f = { a8 fd [2] 9a df [2] 9c ea [2] b2 ea [2] 8d f6 }

  condition:
    any of them
}