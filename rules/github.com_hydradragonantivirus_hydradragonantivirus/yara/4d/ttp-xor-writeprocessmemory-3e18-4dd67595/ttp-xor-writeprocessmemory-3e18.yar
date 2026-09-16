rule TTP_XOR_WriteProcessMemory_3e18 {
  strings:
    $key_3e18 = { 69 6a [2] 5b 48 [2] 5d 7d [2] 73 7d [2] 4c 61 }

  condition:
    any of them
}