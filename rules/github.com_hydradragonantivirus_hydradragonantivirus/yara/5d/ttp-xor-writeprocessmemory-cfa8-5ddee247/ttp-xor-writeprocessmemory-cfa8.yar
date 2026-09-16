rule TTP_XOR_WriteProcessMemory_cfa8 {
  strings:
    $key_cfa8 = { 98 da [2] aa f8 [2] ac cd [2] 82 cd [2] bd d1 }

  condition:
    any of them
}