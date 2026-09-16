rule TTP_XOR_WriteProcessMemory_2b7d {
  strings:
    $key_2b7d = { 7c 0f [2] 4e 2d [2] 48 18 [2] 66 18 [2] 59 04 }

  condition:
    any of them
}