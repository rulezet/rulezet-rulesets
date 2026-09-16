rule TTP_XOR_WriteProcessMemory_708f {
  strings:
    $key_708f = { 27 fd [2] 15 df [2] 13 ea [2] 3d ea [2] 02 f6 }

  condition:
    any of them
}