rule TTP_XOR_WriteProcessMemory_7eff {
  strings:
    $key_7eff = { 29 8d [2] 1b af [2] 1d 9a [2] 33 9a [2] 0c 86 }

  condition:
    any of them
}