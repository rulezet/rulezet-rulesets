rule TTP_XOR_WriteProcessMemory_c983 {
  strings:
    $key_c983 = { 9e f1 [2] ac d3 [2] aa e6 [2] 84 e6 [2] bb fa }

  condition:
    any of them
}