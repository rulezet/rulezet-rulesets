rule TTP_XOR_WriteProcessMemory_283f {
  strings:
    $key_283f = { 7f 4d [2] 4d 6f [2] 4b 5a [2] 65 5a [2] 5a 46 }

  condition:
    any of them
}