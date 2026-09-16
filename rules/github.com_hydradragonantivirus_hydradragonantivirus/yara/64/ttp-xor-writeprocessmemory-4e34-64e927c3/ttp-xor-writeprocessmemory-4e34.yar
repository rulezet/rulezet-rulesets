rule TTP_XOR_WriteProcessMemory_4e34 {
  strings:
    $key_4e34 = { 19 46 [2] 2b 64 [2] 2d 51 [2] 03 51 [2] 3c 4d }

  condition:
    any of them
}