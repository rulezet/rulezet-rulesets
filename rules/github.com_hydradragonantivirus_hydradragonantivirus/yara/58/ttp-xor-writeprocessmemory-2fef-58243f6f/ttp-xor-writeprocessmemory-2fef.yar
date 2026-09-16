rule TTP_XOR_WriteProcessMemory_2fef {
  strings:
    $key_2fef = { 78 9d [2] 4a bf [2] 4c 8a [2] 62 8a [2] 5d 96 }

  condition:
    any of them
}