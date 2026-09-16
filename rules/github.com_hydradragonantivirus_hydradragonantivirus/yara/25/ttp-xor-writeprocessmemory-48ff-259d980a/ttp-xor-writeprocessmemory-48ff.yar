rule TTP_XOR_WriteProcessMemory_48ff {
  strings:
    $key_48ff = { 1f 8d [2] 2d af [2] 2b 9a [2] 05 9a [2] 3a 86 }

  condition:
    any of them
}