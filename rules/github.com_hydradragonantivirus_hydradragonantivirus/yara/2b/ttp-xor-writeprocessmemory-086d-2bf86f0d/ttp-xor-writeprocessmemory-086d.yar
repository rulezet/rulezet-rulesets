rule TTP_XOR_WriteProcessMemory_086d {
  strings:
    $key_086d = { 5f 1f [2] 6d 3d [2] 6b 08 [2] 45 08 [2] 7a 14 }

  condition:
    any of them
}