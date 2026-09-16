rule TTP_XOR_WriteProcessMemory_11e8 {
  strings:
    $key_11e8 = { 46 9a [2] 74 b8 [2] 72 8d [2] 5c 8d [2] 63 91 }

  condition:
    any of them
}