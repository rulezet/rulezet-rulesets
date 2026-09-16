rule TTP_XOR_WriteProcessMemory_6f28 {
  strings:
    $key_6f28 = { 38 5a [2] 0a 78 [2] 0c 4d [2] 22 4d [2] 1d 51 }

  condition:
    any of them
}