rule TTP_XOR_WriteProcessMemory_5e18 {
  strings:
    $key_5e18 = { 09 6a [2] 3b 48 [2] 3d 7d [2] 13 7d [2] 2c 61 }

  condition:
    any of them
}