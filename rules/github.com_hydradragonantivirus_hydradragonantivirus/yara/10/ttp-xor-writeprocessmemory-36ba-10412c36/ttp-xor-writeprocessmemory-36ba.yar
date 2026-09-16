rule TTP_XOR_WriteProcessMemory_36ba {
  strings:
    $key_36ba = { 61 c8 [2] 53 ea [2] 55 df [2] 7b df [2] 44 c3 }

  condition:
    any of them
}