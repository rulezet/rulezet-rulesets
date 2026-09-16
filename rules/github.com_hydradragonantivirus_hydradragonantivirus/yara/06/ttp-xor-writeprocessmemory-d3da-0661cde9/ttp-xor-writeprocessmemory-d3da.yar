rule TTP_XOR_WriteProcessMemory_d3da {
  strings:
    $key_d3da = { 84 a8 [2] b6 8a [2] b0 bf [2] 9e bf [2] a1 a3 }

  condition:
    any of them
}