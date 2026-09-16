rule TTP_XOR_WriteProcessMemory_4c8f {
  strings:
    $key_4c8f = { 1b fd [2] 29 df [2] 2f ea [2] 01 ea [2] 3e f6 }

  condition:
    any of them
}