rule TTP_XOR_WriteProcessMemory_3838 {
  strings:
    $key_3838 = { 6f 4a [2] 5d 68 [2] 5b 5d [2] 75 5d [2] 4a 41 }

  condition:
    any of them
}