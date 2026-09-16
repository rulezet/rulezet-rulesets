rule TTP_XOR_WriteProcessMemory_410f {
  strings:
    $key_410f = { 16 7d [2] 24 5f [2] 22 6a [2] 0c 6a [2] 33 76 }

  condition:
    any of them
}