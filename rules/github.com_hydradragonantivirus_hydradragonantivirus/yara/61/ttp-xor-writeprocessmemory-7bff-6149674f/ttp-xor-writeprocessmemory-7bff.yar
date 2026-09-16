rule TTP_XOR_WriteProcessMemory_7bff {
  strings:
    $key_7bff = { 2c 8d [2] 1e af [2] 18 9a [2] 36 9a [2] 09 86 }

  condition:
    any of them
}