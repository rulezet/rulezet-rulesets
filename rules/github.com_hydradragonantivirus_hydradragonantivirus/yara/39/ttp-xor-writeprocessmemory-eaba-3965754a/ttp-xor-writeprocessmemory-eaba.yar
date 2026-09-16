rule TTP_XOR_WriteProcessMemory_eaba {
  strings:
    $key_eaba = { bd c8 [2] 8f ea [2] 89 df [2] a7 df [2] 98 c3 }

  condition:
    any of them
}