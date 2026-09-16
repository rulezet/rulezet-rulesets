rule TTP_XOR_WriteProcessMemory_4bef {
  strings:
    $key_4bef = { 1c 9d [2] 2e bf [2] 28 8a [2] 06 8a [2] 39 96 }

  condition:
    any of them
}