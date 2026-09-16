rule TTP_XOR_WriteProcessMemory_2aef {
  strings:
    $key_2aef = { 7d 9d [2] 4f bf [2] 49 8a [2] 67 8a [2] 58 96 }

  condition:
    any of them
}