rule TTP_XOR_WriteProcessMemory_2a2d {
  strings:
    $key_2a2d = { 7d 5f [2] 4f 7d [2] 49 48 [2] 67 48 [2] 58 54 }

  condition:
    any of them
}