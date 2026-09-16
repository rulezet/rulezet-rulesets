rule TTP_XOR_WriteProcessMemory_04ba {
  strings:
    $key_04ba = { 53 c8 [2] 61 ea [2] 67 df [2] 49 df [2] 76 c3 }

  condition:
    any of them
}