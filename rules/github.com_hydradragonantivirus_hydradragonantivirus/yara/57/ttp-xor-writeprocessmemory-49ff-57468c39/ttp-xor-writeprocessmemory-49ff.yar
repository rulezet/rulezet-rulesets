rule TTP_XOR_WriteProcessMemory_49ff {
  strings:
    $key_49ff = { 1e 8d [2] 2c af [2] 2a 9a [2] 04 9a [2] 3b 86 }

  condition:
    any of them
}