rule TTP_XOR_WriteProcessMemory_69b6 {
  strings:
    $key_69b6 = { 3e c4 [2] 0c e6 [2] 0a d3 [2] 24 d3 [2] 1b cf }

  condition:
    any of them
}