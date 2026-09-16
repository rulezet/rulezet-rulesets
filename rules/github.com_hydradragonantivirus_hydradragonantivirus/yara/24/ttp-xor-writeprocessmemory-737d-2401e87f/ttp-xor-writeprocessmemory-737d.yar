rule TTP_XOR_WriteProcessMemory_737d {
  strings:
    $key_737d = { 24 0f [2] 16 2d [2] 10 18 [2] 3e 18 [2] 01 04 }

  condition:
    any of them
}