rule TTP_XOR_WriteProcessMemory_2948 {
  strings:
    $key_2948 = { 7e 3a [2] 4c 18 [2] 4a 2d [2] 64 2d [2] 5b 31 }

  condition:
    any of them
}