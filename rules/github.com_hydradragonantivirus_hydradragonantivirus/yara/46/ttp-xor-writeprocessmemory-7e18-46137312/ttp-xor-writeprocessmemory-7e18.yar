rule TTP_XOR_WriteProcessMemory_7e18 {
  strings:
    $key_7e18 = { 29 6a [2] 1b 48 [2] 1d 7d [2] 33 7d [2] 0c 61 }

  condition:
    any of them
}