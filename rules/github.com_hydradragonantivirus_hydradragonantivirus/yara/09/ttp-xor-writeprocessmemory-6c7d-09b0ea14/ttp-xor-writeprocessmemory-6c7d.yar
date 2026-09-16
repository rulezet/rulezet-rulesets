rule TTP_XOR_WriteProcessMemory_6c7d {
  strings:
    $key_6c7d = { 3b 0f [2] 09 2d [2] 0f 18 [2] 21 18 [2] 1e 04 }

  condition:
    any of them
}