rule TTP_XOR_WriteProcessMemory_525a {
  strings:
    $key_525a = { 05 28 [2] 37 0a [2] 31 3f [2] 1f 3f [2] 20 23 }

  condition:
    any of them
}