rule TTP_XOR_WriteProcessMemory_0eef {
  strings:
    $key_0eef = { 59 9d [2] 6b bf [2] 6d 8a [2] 43 8a [2] 7c 96 }

  condition:
    any of them
}