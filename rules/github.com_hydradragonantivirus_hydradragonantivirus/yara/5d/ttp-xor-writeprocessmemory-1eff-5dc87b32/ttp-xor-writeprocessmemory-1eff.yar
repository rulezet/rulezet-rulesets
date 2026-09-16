rule TTP_XOR_WriteProcessMemory_1eff {
  strings:
    $key_1eff = { 49 8d [2] 7b af [2] 7d 9a [2] 53 9a [2] 6c 86 }

  condition:
    any of them
}