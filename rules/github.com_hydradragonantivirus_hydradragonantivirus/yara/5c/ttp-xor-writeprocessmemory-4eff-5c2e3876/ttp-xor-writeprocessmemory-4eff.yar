rule TTP_XOR_WriteProcessMemory_4eff {
  strings:
    $key_4eff = { 19 8d [2] 2b af [2] 2d 9a [2] 03 9a [2] 3c 86 }

  condition:
    any of them
}