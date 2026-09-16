rule TTP_XOR_WriteProcessMemory_7b38 {
  strings:
    $key_7b38 = { 2c 4a [2] 1e 68 [2] 18 5d [2] 36 5d [2] 09 41 }

  condition:
    any of them
}