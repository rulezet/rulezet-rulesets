rule TTP_XOR_WriteProcessMemory_3dca {
  strings:
    $key_3dca = { 6a b8 [2] 58 9a [2] 5e af [2] 70 af [2] 4f b3 }

  condition:
    any of them
}