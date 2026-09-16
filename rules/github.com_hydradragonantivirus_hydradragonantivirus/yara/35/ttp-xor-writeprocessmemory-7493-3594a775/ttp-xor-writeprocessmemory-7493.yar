rule TTP_XOR_WriteProcessMemory_7493 {
  strings:
    $key_7493 = { 23 e1 [2] 11 c3 [2] 17 f6 [2] 39 f6 [2] 06 ea }

  condition:
    any of them
}