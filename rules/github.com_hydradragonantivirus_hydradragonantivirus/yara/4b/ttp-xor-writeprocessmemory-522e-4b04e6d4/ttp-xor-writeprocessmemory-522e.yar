rule TTP_XOR_WriteProcessMemory_522e {
  strings:
    $key_522e = { 05 5c [2] 37 7e [2] 31 4b [2] 1f 4b [2] 20 57 }

  condition:
    any of them
}