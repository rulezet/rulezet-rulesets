rule TTP_XOR_WriteProcessMemory_cfba {
  strings:
    $key_cfba = { 98 c8 [2] aa ea [2] ac df [2] 82 df [2] bd c3 }

  condition:
    any of them
}