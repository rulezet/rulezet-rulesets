rule TTP_XOR_WriteProcessMemory_09b6 {
  strings:
    $key_09b6 = { 5e c4 [2] 6c e6 [2] 6a d3 [2] 44 d3 [2] 7b cf }

  condition:
    any of them
}