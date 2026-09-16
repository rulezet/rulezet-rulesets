rule TTP_XOR_WriteProcessMemory_2d8f {
  strings:
    $key_2d8f = { 7a fd [2] 48 df [2] 4e ea [2] 60 ea [2] 5f f6 }

  condition:
    any of them
}