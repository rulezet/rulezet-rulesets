rule TTP_XOR_WriteProcessMemory_2678 {
  strings:
    $key_2678 = { 71 0a [2] 43 28 [2] 45 1d [2] 6b 1d [2] 54 01 }

  condition:
    any of them
}