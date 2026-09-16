rule TTP_XOR_WriteProcessMemory_577d {
  strings:
    $key_577d = { 00 0f [2] 32 2d [2] 34 18 [2] 1a 18 [2] 25 04 }

  condition:
    any of them
}