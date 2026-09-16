rule TTP_XOR_WriteProcessMemory_7a38 {
  strings:
    $key_7a38 = { 2d 4a [2] 1f 68 [2] 19 5d [2] 37 5d [2] 08 41 }

  condition:
    any of them
}