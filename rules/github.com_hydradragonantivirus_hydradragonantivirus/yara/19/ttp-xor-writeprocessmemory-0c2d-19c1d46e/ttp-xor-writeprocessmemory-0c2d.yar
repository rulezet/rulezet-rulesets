rule TTP_XOR_WriteProcessMemory_0c2d {
  strings:
    $key_0c2d = { 5b 5f [2] 69 7d [2] 6f 48 [2] 41 48 [2] 7e 54 }

  condition:
    any of them
}