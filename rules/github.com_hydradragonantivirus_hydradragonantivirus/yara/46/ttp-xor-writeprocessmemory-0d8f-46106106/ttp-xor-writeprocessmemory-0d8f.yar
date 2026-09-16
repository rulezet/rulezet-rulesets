rule TTP_XOR_WriteProcessMemory_0d8f {
  strings:
    $key_0d8f = { 5a fd [2] 68 df [2] 6e ea [2] 40 ea [2] 7f f6 }

  condition:
    any of them
}