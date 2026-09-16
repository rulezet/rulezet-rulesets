rule TTP_XOR_WriteProcessMemory_c834 {
  strings:
    $key_c834 = { 9f 46 [2] ad 64 [2] ab 51 [2] 85 51 [2] ba 4d }

  condition:
    any of them
}