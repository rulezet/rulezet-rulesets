rule TTP_XOR_WriteProcessMemory_2e18 {
  strings:
    $key_2e18 = { 79 6a [2] 4b 48 [2] 4d 7d [2] 63 7d [2] 5c 61 }

  condition:
    any of them
}