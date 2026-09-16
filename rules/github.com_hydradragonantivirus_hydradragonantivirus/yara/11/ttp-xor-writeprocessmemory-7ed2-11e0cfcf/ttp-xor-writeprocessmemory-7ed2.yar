rule TTP_XOR_WriteProcessMemory_7ed2 {
  strings:
    $key_7ed2 = { 29 a0 [2] 1b 82 [2] 1d b7 [2] 33 b7 [2] 0c ab }

  condition:
    any of them
}