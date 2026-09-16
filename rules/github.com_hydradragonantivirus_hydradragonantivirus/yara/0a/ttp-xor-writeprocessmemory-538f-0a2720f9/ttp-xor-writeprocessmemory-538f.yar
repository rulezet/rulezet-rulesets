rule TTP_XOR_WriteProcessMemory_538f {
  strings:
    $key_538f = { 04 fd [2] 36 df [2] 30 ea [2] 1e ea [2] 21 f6 }

  condition:
    any of them
}