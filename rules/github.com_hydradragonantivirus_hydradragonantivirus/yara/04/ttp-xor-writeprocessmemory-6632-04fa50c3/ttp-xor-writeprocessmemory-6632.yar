rule TTP_XOR_WriteProcessMemory_6632 {
  strings:
    $key_6632 = { 31 40 [2] 03 62 [2] 05 57 [2] 2b 57 [2] 14 4b }

  condition:
    any of them
}