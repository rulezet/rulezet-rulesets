rule TTP_XOR_WriteProcessMemory_671d {
  strings:
    $key_671d = { 30 6f [2] 02 4d [2] 04 78 [2] 2a 78 [2] 15 64 }

  condition:
    any of them
}