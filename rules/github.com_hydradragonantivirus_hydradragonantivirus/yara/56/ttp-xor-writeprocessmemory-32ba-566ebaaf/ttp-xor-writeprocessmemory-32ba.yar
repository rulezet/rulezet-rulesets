rule TTP_XOR_WriteProcessMemory_32ba {
  strings:
    $key_32ba = { 65 c8 [2] 57 ea [2] 51 df [2] 7f df [2] 40 c3 }

  condition:
    any of them
}