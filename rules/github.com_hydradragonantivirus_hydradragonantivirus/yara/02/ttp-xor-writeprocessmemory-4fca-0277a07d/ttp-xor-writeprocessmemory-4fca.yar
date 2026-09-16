rule TTP_XOR_WriteProcessMemory_4fca {
  strings:
    $key_4fca = { 18 b8 [2] 2a 9a [2] 2c af [2] 02 af [2] 3d b3 }

  condition:
    any of them
}