rule TTP_XOR_WriteProcessMemory_3948 {
  strings:
    $key_3948 = { 6e 3a [2] 5c 18 [2] 5a 2d [2] 74 2d [2] 4b 31 }

  condition:
    any of them
}