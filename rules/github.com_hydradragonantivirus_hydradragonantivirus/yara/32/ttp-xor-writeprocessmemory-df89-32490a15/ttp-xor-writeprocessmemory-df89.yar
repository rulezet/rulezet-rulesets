rule TTP_XOR_WriteProcessMemory_df89 {
  strings:
    $key_df89 = { 88 fb [2] ba d9 [2] bc ec [2] 92 ec [2] ad f0 }

  condition:
    any of them
}