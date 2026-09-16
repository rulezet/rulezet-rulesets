rule TTP_XOR_WriteProcessMemory_66ba {
  strings:
    $key_66ba = { 31 c8 [2] 03 ea [2] 05 df [2] 2b df [2] 14 c3 }

  condition:
    any of them
}