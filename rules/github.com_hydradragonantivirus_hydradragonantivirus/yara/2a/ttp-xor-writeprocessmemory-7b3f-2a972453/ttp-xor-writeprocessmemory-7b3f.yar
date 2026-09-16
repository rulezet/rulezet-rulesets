rule TTP_XOR_WriteProcessMemory_7b3f {
  strings:
    $key_7b3f = { 2c 4d [2] 1e 6f [2] 18 5a [2] 36 5a [2] 09 46 }

  condition:
    any of them
}