rule TTP_XOR_WriteProcessMemory_147d {
  strings:
    $key_147d = { 43 0f [2] 71 2d [2] 77 18 [2] 59 18 [2] 66 04 }

  condition:
    any of them
}