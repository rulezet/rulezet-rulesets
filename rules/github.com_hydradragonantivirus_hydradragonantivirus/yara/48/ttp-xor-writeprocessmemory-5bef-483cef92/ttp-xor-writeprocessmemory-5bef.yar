rule TTP_XOR_WriteProcessMemory_5bef {
  strings:
    $key_5bef = { 0c 9d [2] 3e bf [2] 38 8a [2] 16 8a [2] 29 96 }

  condition:
    any of them
}