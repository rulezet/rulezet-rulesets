rule TTP_XOR_WriteProcessMemory_48f5 {
  strings:
    $key_48f5 = { 1f 87 [2] 2d a5 [2] 2b 90 [2] 05 90 [2] 3a 8c }

  condition:
    any of them
}