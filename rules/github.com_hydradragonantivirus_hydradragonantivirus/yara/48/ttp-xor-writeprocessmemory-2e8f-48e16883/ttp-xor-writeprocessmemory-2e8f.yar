rule TTP_XOR_WriteProcessMemory_2e8f {
  strings:
    $key_2e8f = { 79 fd [2] 4b df [2] 4d ea [2] 63 ea [2] 5c f6 }

  condition:
    any of them
}