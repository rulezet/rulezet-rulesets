rule TTP_XOR_WriteProcessMemory_7a48 {
  strings:
    $key_7a48 = { 2d 3a [2] 1f 18 [2] 19 2d [2] 37 2d [2] 08 31 }

  condition:
    any of them
}