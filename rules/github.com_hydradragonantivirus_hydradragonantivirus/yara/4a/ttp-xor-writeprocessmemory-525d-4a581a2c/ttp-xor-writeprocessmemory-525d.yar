rule TTP_XOR_WriteProcessMemory_525d {
  strings:
    $key_525d = { 05 2f [2] 37 0d [2] 31 38 [2] 1f 38 [2] 20 24 }

  condition:
    any of them
}