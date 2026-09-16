rule TTP_XOR_WriteProcessMemory_4ed2 {
  strings:
    $key_4ed2 = { 19 a0 [2] 2b 82 [2] 2d b7 [2] 03 b7 [2] 3c ab }

  condition:
    any of them
}