rule TTP_XOR_WriteProcessMemory_747d {
  strings:
    $key_747d = { 23 0f [2] 11 2d [2] 17 18 [2] 39 18 [2] 06 04 }

  condition:
    any of them
}