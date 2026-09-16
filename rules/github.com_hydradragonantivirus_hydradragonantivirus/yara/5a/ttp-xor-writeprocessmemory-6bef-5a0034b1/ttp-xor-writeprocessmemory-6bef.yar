rule TTP_XOR_WriteProcessMemory_6bef {
  strings:
    $key_6bef = { 3c 9d [2] 0e bf [2] 08 8a [2] 26 8a [2] 19 96 }

  condition:
    any of them
}