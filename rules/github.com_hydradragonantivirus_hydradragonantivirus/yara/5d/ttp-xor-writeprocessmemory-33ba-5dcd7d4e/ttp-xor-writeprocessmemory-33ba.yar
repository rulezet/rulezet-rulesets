rule TTP_XOR_WriteProcessMemory_33ba {
  strings:
    $key_33ba = { 64 c8 [2] 56 ea [2] 50 df [2] 7e df [2] 41 c3 }

  condition:
    any of them
}