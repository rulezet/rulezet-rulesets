rule TTP_XOR_WriteProcessMemory_ee8f {
  strings:
    $key_ee8f = { b9 fd [2] 8b df [2] 8d ea [2] a3 ea [2] 9c f6 }

  condition:
    any of them
}