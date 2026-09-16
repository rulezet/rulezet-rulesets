rule TTP_XOR_WriteProcessMemory_c92d {
  strings:
    $key_c92d = { 9e 5f [2] ac 7d [2] aa 48 [2] 84 48 [2] bb 54 }

  condition:
    any of them
}