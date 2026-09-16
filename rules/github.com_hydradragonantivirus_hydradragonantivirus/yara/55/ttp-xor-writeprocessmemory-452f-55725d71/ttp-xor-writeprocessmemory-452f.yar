rule TTP_XOR_WriteProcessMemory_452f {
  strings:
    $key_452f = { 12 5d [2] 20 7f [2] 26 4a [2] 08 4a [2] 37 56 }

  condition:
    any of them
}