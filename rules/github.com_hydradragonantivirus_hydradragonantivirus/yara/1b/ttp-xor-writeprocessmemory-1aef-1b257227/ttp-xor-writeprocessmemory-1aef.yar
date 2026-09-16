rule TTP_XOR_WriteProcessMemory_1aef {
  strings:
    $key_1aef = { 4d 9d [2] 7f bf [2] 79 8a [2] 57 8a [2] 68 96 }

  condition:
    any of them
}