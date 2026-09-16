rule TTP_XOR_WriteProcessMemory_70ba {
  strings:
    $key_70ba = { 27 c8 [2] 15 ea [2] 13 df [2] 3d df [2] 02 c3 }

  condition:
    any of them
}