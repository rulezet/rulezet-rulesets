rule TTP_XOR_WriteProcessMemory_3d3a {
  strings:
    $key_3d3a = { 6a 48 [2] 58 6a [2] 5e 5f [2] 70 5f [2] 4f 43 }

  condition:
    any of them
}