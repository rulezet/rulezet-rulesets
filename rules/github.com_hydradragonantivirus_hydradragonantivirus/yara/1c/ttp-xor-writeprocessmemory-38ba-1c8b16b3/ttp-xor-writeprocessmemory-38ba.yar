rule TTP_XOR_WriteProcessMemory_38ba {
  strings:
    $key_38ba = { 6f c8 [2] 5d ea [2] 5b df [2] 75 df [2] 4a c3 }

  condition:
    any of them
}