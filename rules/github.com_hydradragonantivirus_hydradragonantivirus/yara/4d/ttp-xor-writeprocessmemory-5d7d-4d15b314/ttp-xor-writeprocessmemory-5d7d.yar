rule TTP_XOR_WriteProcessMemory_5d7d {
  strings:
    $key_5d7d = { 0a 0f [2] 38 2d [2] 3e 18 [2] 10 18 [2] 2f 04 }

  condition:
    any of them
}