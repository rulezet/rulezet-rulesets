rule TTP_XOR_WriteProcessMemory_383d {
  strings:
    $key_383d = { 6f 4f [2] 5d 6d [2] 5b 58 [2] 75 58 [2] 4a 44 }

  condition:
    any of them
}