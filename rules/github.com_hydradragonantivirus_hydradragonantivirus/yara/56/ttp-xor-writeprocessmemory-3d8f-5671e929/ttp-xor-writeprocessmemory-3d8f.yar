rule TTP_XOR_WriteProcessMemory_3d8f {
  strings:
    $key_3d8f = { 6a fd [2] 58 df [2] 5e ea [2] 70 ea [2] 4f f6 }

  condition:
    any of them
}