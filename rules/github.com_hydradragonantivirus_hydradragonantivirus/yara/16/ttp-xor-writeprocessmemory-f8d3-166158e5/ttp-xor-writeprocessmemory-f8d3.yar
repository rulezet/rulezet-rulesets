rule TTP_XOR_WriteProcessMemory_f8d3 {
  strings:
    $key_f8d3 = { af a1 [2] 9d 83 [2] 9b b6 [2] b5 b6 [2] 8a aa }

  condition:
    any of them
}