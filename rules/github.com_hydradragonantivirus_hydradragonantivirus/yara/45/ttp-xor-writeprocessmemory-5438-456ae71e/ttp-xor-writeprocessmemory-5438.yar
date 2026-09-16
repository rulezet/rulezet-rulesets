rule TTP_XOR_WriteProcessMemory_5438 {
  strings:
    $key_5438 = { 03 4a [2] 31 68 [2] 37 5d [2] 19 5d [2] 26 41 }

  condition:
    any of them
}