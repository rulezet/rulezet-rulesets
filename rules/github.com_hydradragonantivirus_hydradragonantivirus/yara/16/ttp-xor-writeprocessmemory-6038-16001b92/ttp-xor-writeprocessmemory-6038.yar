rule TTP_XOR_WriteProcessMemory_6038 {
  strings:
    $key_6038 = { 37 4a [2] 05 68 [2] 03 5d [2] 2d 5d [2] 12 41 }

  condition:
    any of them
}