rule TTP_XOR_WriteProcessMemory_340a {
  strings:
    $key_340a = { 63 78 [2] 51 5a [2] 57 6f [2] 79 6f [2] 46 73 }

  condition:
    any of them
}