rule TTP_XOR_WriteProcessMemory_4c48 {
  strings:
    $key_4c48 = { 1b 3a [2] 29 18 [2] 2f 2d [2] 01 2d [2] 3e 31 }

  condition:
    any of them
}