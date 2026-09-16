rule TTP_XOR_WriteProcessMemory_6b38 {
  strings:
    $key_6b38 = { 3c 4a [2] 0e 68 [2] 08 5d [2] 26 5d [2] 19 41 }

  condition:
    any of them
}