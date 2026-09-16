rule TTP_XOR_WriteProcessMemory_011f {
  strings:
    $key_011f = { 56 6d [2] 64 4f [2] 62 7a [2] 4c 7a [2] 73 66 }

  condition:
    any of them
}