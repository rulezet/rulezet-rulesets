rule TTP_XOR_WriteProcessMemory_7d3a {
  strings:
    $key_7d3a = { 2a 48 [2] 18 6a [2] 1e 5f [2] 30 5f [2] 0f 43 }

  condition:
    any of them
}