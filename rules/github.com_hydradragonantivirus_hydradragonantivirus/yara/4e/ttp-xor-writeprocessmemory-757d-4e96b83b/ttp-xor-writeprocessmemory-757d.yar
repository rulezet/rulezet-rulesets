rule TTP_XOR_WriteProcessMemory_757d {
  strings:
    $key_757d = { 22 0f [2] 10 2d [2] 16 18 [2] 38 18 [2] 07 04 }

  condition:
    any of them
}