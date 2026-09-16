rule TTP_XOR_WriteProcessMemory_5a38 {
  strings:
    $key_5a38 = { 0d 4a [2] 3f 68 [2] 39 5d [2] 17 5d [2] 28 41 }

  condition:
    any of them
}