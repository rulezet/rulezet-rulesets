rule TTP_XOR_WriteProcessMemory_d3cd {
  strings:
    $key_d3cd = { 84 bf [2] b6 9d [2] b0 a8 [2] 9e a8 [2] a1 b4 }

  condition:
    any of them
}