rule TTP_XOR_WriteProcessMemory_d3ef {
  strings:
    $key_d3ef = { 84 9d [2] b6 bf [2] b0 8a [2] 9e 8a [2] a1 96 }

  condition:
    any of them
}