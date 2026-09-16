rule TTP_XOR_WriteProcessMemory_490f {
  strings:
    $key_490f = { 1e 7d [2] 2c 5f [2] 2a 6a [2] 04 6a [2] 3b 76 }

  condition:
    any of them
}