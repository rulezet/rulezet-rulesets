rule TTP_XOR_WriteProcessMemory_79b6 {
  strings:
    $key_79b6 = { 2e c4 [2] 1c e6 [2] 1a d3 [2] 34 d3 [2] 0b cf }

  condition:
    any of them
}