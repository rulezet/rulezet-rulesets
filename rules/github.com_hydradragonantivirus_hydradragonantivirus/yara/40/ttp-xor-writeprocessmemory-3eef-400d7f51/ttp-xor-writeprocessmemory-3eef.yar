rule TTP_XOR_WriteProcessMemory_3eef {
  strings:
    $key_3eef = { 69 9d [2] 5b bf [2] 5d 8a [2] 73 8a [2] 4c 96 }

  condition:
    any of them
}