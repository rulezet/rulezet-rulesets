rule TTP_XOR_WriteProcessMemory_62ba {
  strings:
    $key_62ba = { 35 c8 [2] 07 ea [2] 01 df [2] 2f df [2] 10 c3 }

  condition:
    any of them
}