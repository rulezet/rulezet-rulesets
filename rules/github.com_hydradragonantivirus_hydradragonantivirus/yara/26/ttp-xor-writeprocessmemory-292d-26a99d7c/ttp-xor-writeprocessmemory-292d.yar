rule TTP_XOR_WriteProcessMemory_292d {
  strings:
    $key_292d = { 7e 5f [2] 4c 7d [2] 4a 48 [2] 64 48 [2] 5b 54 }

  condition:
    any of them
}