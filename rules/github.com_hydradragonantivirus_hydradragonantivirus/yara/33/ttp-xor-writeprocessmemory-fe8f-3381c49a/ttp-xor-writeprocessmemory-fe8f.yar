rule TTP_XOR_WriteProcessMemory_fe8f {
  strings:
    $key_fe8f = { a9 fd [2] 9b df [2] 9d ea [2] b3 ea [2] 8c f6 }

  condition:
    any of them
}