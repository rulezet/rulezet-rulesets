rule TTP_XOR_WriteProcessMemory_511d {
  strings:
    $key_511d = { 06 6f [2] 34 4d [2] 32 78 [2] 1c 78 [2] 23 64 }

  condition:
    any of them
}