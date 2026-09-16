rule TTP_XOR_WriteProcessMemory_525c {
  strings:
    $key_525c = { 05 2e [2] 37 0c [2] 31 39 [2] 1f 39 [2] 20 25 }

  condition:
    any of them
}