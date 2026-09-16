rule TTP_XOR_WriteProcessMemory_2ab6 {
  strings:
    $key_2ab6 = { 7d c4 [2] 4f e6 [2] 49 d3 [2] 67 d3 [2] 58 cf }

  condition:
    any of them
}