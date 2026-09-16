rule TTP_XOR_WriteProcessMemory_731d {
  strings:
    $key_731d = { 24 6f [2] 16 4d [2] 10 78 [2] 3e 78 [2] 01 64 }

  condition:
    any of them
}