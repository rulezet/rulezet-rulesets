rule TTP_XOR_WriteProcessMemory_2d7d {
  strings:
    $key_2d7d = { 7a 0f [2] 48 2d [2] 4e 18 [2] 60 18 [2] 5f 04 }

  condition:
    any of them
}