rule TTP_XOR_WriteProcessMemory_1c8f {
  strings:
    $key_1c8f = { 4b fd [2] 79 df [2] 7f ea [2] 51 ea [2] 6e f6 }

  condition:
    any of them
}