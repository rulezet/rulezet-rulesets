rule TTP_XOR_WriteProcessMemory_4828 {
  strings:
    $key_4828 = { 1f 5a [2] 2d 78 [2] 2b 4d [2] 05 4d [2] 3a 51 }

  condition:
    any of them
}