rule TTP_XOR_WriteProcessMemory_e2ba {
  strings:
    $key_e2ba = { b5 c8 [2] 87 ea [2] 81 df [2] af df [2] 90 c3 }

  condition:
    any of them
}