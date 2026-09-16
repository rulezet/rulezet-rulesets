rule TTP_XOR_WriteProcessMemory_2c8f {
  strings:
    $key_2c8f = { 7b fd [2] 49 df [2] 4f ea [2] 61 ea [2] 5e f6 }

  condition:
    any of them
}