rule TTP_XOR_WriteProcessMemory_6e8f {
  strings:
    $key_6e8f = { 39 fd [2] 0b df [2] 0d ea [2] 23 ea [2] 1c f6 }

  condition:
    any of them
}