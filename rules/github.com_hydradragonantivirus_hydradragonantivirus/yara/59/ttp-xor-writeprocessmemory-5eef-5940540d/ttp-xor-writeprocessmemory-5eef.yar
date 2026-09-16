rule TTP_XOR_WriteProcessMemory_5eef {
  strings:
    $key_5eef = { 09 9d [2] 3b bf [2] 3d 8a [2] 13 8a [2] 2c 96 }

  condition:
    any of them
}