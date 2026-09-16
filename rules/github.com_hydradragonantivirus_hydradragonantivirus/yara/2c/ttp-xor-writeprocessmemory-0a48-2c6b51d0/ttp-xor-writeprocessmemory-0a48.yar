rule TTP_XOR_WriteProcessMemory_0a48 {
  strings:
    $key_0a48 = { 5d 3a [2] 6f 18 [2] 69 2d [2] 47 2d [2] 78 31 }

  condition:
    any of them
}