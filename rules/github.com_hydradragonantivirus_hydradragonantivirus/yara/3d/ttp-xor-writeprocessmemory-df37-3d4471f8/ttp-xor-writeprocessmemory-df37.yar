rule TTP_XOR_WriteProcessMemory_df37 {
  strings:
    $key_df37 = { 88 45 [2] ba 67 [2] bc 52 [2] 92 52 [2] ad 4e }

  condition:
    any of them
}