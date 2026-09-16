rule TTP_XOR_WriteProcessMemory_0c7d {
  strings:
    $key_0c7d = { 5b 0f [2] 69 2d [2] 6f 18 [2] 41 18 [2] 7e 04 }

  condition:
    any of them
}