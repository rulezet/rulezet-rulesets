rule TTP_XOR_WriteProcessMemory_5fef {
  strings:
    $key_5fef = { 08 9d [2] 3a bf [2] 3c 8a [2] 12 8a [2] 2d 96 }

  condition:
    any of them
}