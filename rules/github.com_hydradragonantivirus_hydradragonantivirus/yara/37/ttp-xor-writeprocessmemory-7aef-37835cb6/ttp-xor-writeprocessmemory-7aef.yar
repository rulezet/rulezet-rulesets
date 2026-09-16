rule TTP_XOR_WriteProcessMemory_7aef {
  strings:
    $key_7aef = { 2d 9d [2] 1f bf [2] 19 8a [2] 37 8a [2] 08 96 }

  condition:
    any of them
}