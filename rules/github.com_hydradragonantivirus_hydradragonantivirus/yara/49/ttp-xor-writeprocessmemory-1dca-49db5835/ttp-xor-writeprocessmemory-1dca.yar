rule TTP_XOR_WriteProcessMemory_1dca {
  strings:
    $key_1dca = { 4a b8 [2] 78 9a [2] 7e af [2] 50 af [2] 6f b3 }

  condition:
    any of them
}