rule TTP_XOR_WriteProcessMemory_0eff {
  strings:
    $key_0eff = { 59 8d [2] 6b af [2] 6d 9a [2] 43 9a [2] 7c 86 }

  condition:
    any of them
}