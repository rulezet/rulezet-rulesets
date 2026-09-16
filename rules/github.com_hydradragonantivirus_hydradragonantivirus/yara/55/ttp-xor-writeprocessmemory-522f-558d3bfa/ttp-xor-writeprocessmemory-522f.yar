rule TTP_XOR_WriteProcessMemory_522f {
  strings:
    $key_522f = { 05 5d [2] 37 7f [2] 31 4a [2] 1f 4a [2] 20 56 }

  condition:
    any of them
}