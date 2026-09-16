rule TTP_XOR_WriteProcessMemory_5d3a {
  strings:
    $key_5d3a = { 0a 48 [2] 38 6a [2] 3e 5f [2] 10 5f [2] 2f 43 }

  condition:
    any of them
}