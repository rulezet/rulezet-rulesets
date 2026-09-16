rule TTP_XOR_WriteProcessMemory_7bef {
  strings:
    $key_7bef = { 2c 9d [2] 1e bf [2] 18 8a [2] 36 8a [2] 09 96 }

  condition:
    any of them
}