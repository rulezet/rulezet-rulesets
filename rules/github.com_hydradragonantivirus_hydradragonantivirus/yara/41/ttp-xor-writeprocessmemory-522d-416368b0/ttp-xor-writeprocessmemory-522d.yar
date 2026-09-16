rule TTP_XOR_WriteProcessMemory_522d {
  strings:
    $key_522d = { 05 5f [2] 37 7d [2] 31 48 [2] 1f 48 [2] 20 54 }

  condition:
    any of them
}