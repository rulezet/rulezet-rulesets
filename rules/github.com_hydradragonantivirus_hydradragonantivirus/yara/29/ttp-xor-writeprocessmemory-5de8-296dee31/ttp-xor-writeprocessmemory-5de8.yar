rule TTP_XOR_WriteProcessMemory_5de8 {
  strings:
    $key_5de8 = { 0a 9a [2] 38 b8 [2] 3e 8d [2] 10 8d [2] 2f 91 }

  condition:
    any of them
}