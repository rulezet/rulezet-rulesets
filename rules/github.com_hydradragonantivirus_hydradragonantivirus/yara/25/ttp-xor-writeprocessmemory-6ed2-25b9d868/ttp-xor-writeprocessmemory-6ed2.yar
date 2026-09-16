rule TTP_XOR_WriteProcessMemory_6ed2 {
  strings:
    $key_6ed2 = { 39 a0 [2] 0b 82 [2] 0d b7 [2] 23 b7 [2] 1c ab }

  condition:
    any of them
}