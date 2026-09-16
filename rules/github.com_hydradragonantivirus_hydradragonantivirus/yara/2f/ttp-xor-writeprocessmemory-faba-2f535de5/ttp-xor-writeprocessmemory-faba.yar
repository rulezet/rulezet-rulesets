rule TTP_XOR_WriteProcessMemory_faba {
  strings:
    $key_faba = { ad c8 [2] 9f ea [2] 99 df [2] b7 df [2] 88 c3 }

  condition:
    any of them
}