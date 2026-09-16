rule TTP_XOR_WriteProcessMemory_2d3a {
  strings:
    $key_2d3a = { 7a 48 [2] 48 6a [2] 4e 5f [2] 60 5f [2] 5f 43 }

  condition:
    any of them
}