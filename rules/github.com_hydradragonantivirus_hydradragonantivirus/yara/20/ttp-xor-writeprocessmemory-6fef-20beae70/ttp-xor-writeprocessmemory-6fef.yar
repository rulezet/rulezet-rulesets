rule TTP_XOR_WriteProcessMemory_6fef {
  strings:
    $key_6fef = { 38 9d [2] 0a bf [2] 0c 8a [2] 22 8a [2] 1d 96 }

  condition:
    any of them
}