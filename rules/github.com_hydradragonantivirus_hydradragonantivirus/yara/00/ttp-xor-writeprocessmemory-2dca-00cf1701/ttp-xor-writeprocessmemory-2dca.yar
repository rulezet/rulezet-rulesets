rule TTP_XOR_WriteProcessMemory_2dca {
  strings:
    $key_2dca = { 7a b8 [2] 48 9a [2] 4e af [2] 60 af [2] 5f b3 }

  condition:
    any of them
}