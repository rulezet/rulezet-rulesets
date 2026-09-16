rule TTP_XOR_WriteProcessMemory_6b7d {
  strings:
    $key_6b7d = { 3c 0f [2] 0e 2d [2] 08 18 [2] 26 18 [2] 19 04 }

  condition:
    any of them
}