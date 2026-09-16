rule TTP_XOR_WriteProcessMemory_52f5 {
  strings:
    $key_52f5 = { 05 87 [2] 37 a5 [2] 31 90 [2] 1f 90 [2] 20 8c }

  condition:
    any of them
}