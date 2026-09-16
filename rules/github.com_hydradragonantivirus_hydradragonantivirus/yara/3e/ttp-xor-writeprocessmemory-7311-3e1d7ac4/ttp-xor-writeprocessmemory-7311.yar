rule TTP_XOR_WriteProcessMemory_7311 {
  strings:
    $key_7311 = { 24 63 [2] 16 41 [2] 10 74 [2] 3e 74 [2] 01 68 }

  condition:
    any of them
}