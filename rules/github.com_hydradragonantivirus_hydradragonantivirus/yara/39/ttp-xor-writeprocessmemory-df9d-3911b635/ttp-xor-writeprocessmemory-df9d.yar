rule TTP_XOR_WriteProcessMemory_df9d {
  strings:
    $key_df9d = { 88 ef [2] ba cd [2] bc f8 [2] 92 f8 [2] ad e4 }

  condition:
    any of them
}