rule TTP_XOR_WriteProcessMemory_1d38 {
  strings:
    $key_1d38 = { 4a 4a [2] 78 68 [2] 7e 5d [2] 50 5d [2] 6f 41 }

  condition:
    any of them
}