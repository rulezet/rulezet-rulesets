rule TTP_XOR_WriteProcessMemory_7653 {
  strings:
    $key_7653 = { 21 21 [2] 13 03 [2] 15 36 [2] 3b 36 [2] 04 2a }

  condition:
    any of them
}