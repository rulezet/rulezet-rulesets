rule TTP_XOR_WriteProcessMemory_e9b6 {
  strings:
    $key_e9b6 = { be c4 [2] 8c e6 [2] 8a d3 [2] a4 d3 [2] 9b cf }

  condition:
    any of them
}