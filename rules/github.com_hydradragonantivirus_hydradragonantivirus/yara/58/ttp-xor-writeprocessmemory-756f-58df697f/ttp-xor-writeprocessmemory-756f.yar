rule TTP_XOR_WriteProcessMemory_756f {
  strings:
    $key_756f = { 22 1d [2] 10 3f [2] 16 0a [2] 38 0a [2] 07 16 }

  condition:
    any of them
}