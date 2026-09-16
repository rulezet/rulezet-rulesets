rule TTP_XOR_WriteProcessMemory_3fca {
  strings:
    $key_3fca = { 68 b8 [2] 5a 9a [2] 5c af [2] 72 af [2] 4d b3 }

  condition:
    any of them
}