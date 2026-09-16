rule TTP_XOR_WriteProcessMemory_1d8f {
  strings:
    $key_1d8f = { 4a fd [2] 78 df [2] 7e ea [2] 50 ea [2] 6f f6 }

  condition:
    any of them
}