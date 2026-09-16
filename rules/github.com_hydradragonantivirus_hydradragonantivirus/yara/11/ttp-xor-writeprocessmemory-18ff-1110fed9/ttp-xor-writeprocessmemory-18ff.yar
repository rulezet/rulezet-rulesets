rule TTP_XOR_WriteProcessMemory_18ff {
  strings:
    $key_18ff = { 4f 8d [2] 7d af [2] 7b 9a [2] 55 9a [2] 6a 86 }

  condition:
    any of them
}