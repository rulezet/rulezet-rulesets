rule TTP_XOR_WriteProcessMemory_0bef {
  strings:
    $key_0bef = { 5c 9d [2] 6e bf [2] 68 8a [2] 46 8a [2] 79 96 }

  condition:
    any of them
}