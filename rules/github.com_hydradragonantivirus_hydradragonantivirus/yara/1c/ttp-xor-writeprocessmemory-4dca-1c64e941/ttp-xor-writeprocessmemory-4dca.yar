rule TTP_XOR_WriteProcessMemory_4dca {
  strings:
    $key_4dca = { 1a b8 [2] 28 9a [2] 2e af [2] 00 af [2] 3f b3 }

  condition:
    any of them
}