rule TTP_XOR_WriteProcessMemory_df8a {
  strings:
    $key_df8a = { 88 f8 [2] ba da [2] bc ef [2] 92 ef [2] ad f3 }

  condition:
    any of them
}