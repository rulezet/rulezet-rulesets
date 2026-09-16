rule TTP_XOR_WriteProcessMemory_0d3f {
  strings:
    $key_0d3f = { 5a 4d [2] 68 6f [2] 6e 5a [2] 40 5a [2] 7f 46 }

  condition:
    any of them
}