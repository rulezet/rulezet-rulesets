rule TTP_XOR_WriteProcessMemory_411f {
  strings:
    $key_411f = { 16 6d [2] 24 4f [2] 22 7a [2] 0c 7a [2] 33 66 }

  condition:
    any of them
}