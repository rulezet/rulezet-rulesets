rule TTP_XOR_WriteProcessMemory_767d {
  strings:
    $key_767d = { 21 0f [2] 13 2d [2] 15 18 [2] 3b 18 [2] 04 04 }

  condition:
    any of them
}