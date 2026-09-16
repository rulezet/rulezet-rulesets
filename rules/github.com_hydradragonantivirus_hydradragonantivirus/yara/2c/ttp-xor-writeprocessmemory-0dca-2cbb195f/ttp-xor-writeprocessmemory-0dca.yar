rule TTP_XOR_WriteProcessMemory_0dca {
  strings:
    $key_0dca = { 5a b8 [2] 68 9a [2] 6e af [2] 40 af [2] 7f b3 }

  condition:
    any of them
}