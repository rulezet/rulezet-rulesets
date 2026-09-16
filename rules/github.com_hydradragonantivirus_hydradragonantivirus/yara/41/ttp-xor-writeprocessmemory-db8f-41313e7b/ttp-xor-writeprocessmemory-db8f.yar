rule TTP_XOR_WriteProcessMemory_db8f {
  strings:
    $key_db8f = { 8c fd [2] be df [2] b8 ea [2] 96 ea [2] a9 f6 }

  condition:
    any of them
}