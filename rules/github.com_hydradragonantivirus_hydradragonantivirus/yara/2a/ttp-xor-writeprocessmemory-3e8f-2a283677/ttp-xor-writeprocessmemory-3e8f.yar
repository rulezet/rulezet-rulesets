rule TTP_XOR_WriteProcessMemory_3e8f {
  strings:
    $key_3e8f = { 69 fd [2] 5b df [2] 5d ea [2] 73 ea [2] 4c f6 }

  condition:
    any of them
}