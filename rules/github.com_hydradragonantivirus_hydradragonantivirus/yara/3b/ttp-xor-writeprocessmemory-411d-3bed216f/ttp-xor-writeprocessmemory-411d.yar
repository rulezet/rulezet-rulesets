rule TTP_XOR_WriteProcessMemory_411d {
  strings:
    $key_411d = { 16 6f [2] 24 4d [2] 22 78 [2] 0c 78 [2] 33 64 }

  condition:
    any of them
}