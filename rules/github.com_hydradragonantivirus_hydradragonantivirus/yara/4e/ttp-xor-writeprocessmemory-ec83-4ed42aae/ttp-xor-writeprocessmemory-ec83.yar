rule TTP_XOR_WriteProcessMemory_ec83 {
  strings:
    $key_ec83 = { bb f1 [2] 89 d3 [2] 8f e6 [2] a1 e6 [2] 9e fa }

  condition:
    any of them
}