rule TTP_XOR_WriteProcessMemory_3eff {
  strings:
    $key_3eff = { 69 8d [2] 5b af [2] 5d 9a [2] 73 9a [2] 4c 86 }

  condition:
    any of them
}