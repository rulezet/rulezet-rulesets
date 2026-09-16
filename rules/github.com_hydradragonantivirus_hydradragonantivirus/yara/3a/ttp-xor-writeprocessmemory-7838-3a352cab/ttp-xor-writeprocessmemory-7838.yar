rule TTP_XOR_WriteProcessMemory_7838 {
  strings:
    $key_7838 = { 2f 4a [2] 1d 68 [2] 1b 5d [2] 35 5d [2] 0a 41 }

  condition:
    any of them
}