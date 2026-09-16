rule TTP_XOR_WriteProcessMemory_1d3f {
  strings:
    $key_1d3f = { 4a 4d [2] 78 6f [2] 7e 5a [2] 50 5a [2] 6f 46 }

  condition:
    any of them
}