rule TTP_XOR_WriteProcessMemory_773f {
  strings:
    $key_773f = { 20 4d [2] 12 6f [2] 14 5a [2] 3a 5a [2] 05 46 }

  condition:
    any of them
}