rule TTP_XOR_WriteProcessMemory_0c48 {
  strings:
    $key_0c48 = { 5b 3a [2] 69 18 [2] 6f 2d [2] 41 2d [2] 7e 31 }

  condition:
    any of them
}