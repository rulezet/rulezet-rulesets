rule TTP_XOR_WriteProcessMemory_6770 {
  strings:
    $key_6770 = { 30 02 [2] 02 20 [2] 04 15 [2] 2a 15 [2] 15 09 }

  condition:
    any of them
}