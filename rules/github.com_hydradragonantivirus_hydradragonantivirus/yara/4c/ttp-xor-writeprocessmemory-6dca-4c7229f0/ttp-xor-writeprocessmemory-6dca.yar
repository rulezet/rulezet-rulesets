rule TTP_XOR_WriteProcessMemory_6dca {
  strings:
    $key_6dca = { 3a b8 [2] 08 9a [2] 0e af [2] 20 af [2] 1f b3 }

  condition:
    any of them
}