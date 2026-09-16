rule TTP_XOR_WriteProcessMemory_df8f {
  strings:
    $key_df8f = { 88 fd [2] ba df [2] bc ea [2] 92 ea [2] ad f6 }

  condition:
    any of them
}