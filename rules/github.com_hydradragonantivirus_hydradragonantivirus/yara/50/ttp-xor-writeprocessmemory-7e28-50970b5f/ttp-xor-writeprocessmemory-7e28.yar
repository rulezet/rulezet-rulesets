rule TTP_XOR_WriteProcessMemory_7e28 {
  strings:
    $key_7e28 = { 29 5a [2] 1b 78 [2] 1d 4d [2] 33 4d [2] 0c 51 }

  condition:
    any of them
}