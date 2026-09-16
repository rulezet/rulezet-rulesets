rule TTP_XOR_WriteProcessMemory_6eef {
  strings:
    $key_6eef = { 39 9d [2] 0b bf [2] 0d 8a [2] 23 8a [2] 1c 96 }

  condition:
    any of them
}