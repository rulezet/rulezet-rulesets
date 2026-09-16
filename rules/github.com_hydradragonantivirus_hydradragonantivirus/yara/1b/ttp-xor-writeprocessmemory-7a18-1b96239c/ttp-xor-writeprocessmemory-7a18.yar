rule TTP_XOR_WriteProcessMemory_7a18 {
  strings:
    $key_7a18 = { 2d 6a [2] 1f 48 [2] 19 7d [2] 37 7d [2] 08 61 }

  condition:
    any of them
}