rule TTP_XOR_WriteProcessMemory_2eff {
  strings:
    $key_2eff = { 79 8d [2] 4b af [2] 4d 9a [2] 63 9a [2] 5c 86 }

  condition:
    any of them
}