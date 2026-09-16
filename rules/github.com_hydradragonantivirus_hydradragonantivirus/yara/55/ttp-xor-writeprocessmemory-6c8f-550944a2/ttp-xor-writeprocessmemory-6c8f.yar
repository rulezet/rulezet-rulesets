rule TTP_XOR_WriteProcessMemory_6c8f {
  strings:
    $key_6c8f = { 3b fd [2] 09 df [2] 0f ea [2] 21 ea [2] 1e f6 }

  condition:
    any of them
}