rule TTP_XOR_WriteProcessMemory_0948 {
  strings:
    $key_0948 = { 5e 3a [2] 6c 18 [2] 6a 2d [2] 44 2d [2] 7b 31 }

  condition:
    any of them
}