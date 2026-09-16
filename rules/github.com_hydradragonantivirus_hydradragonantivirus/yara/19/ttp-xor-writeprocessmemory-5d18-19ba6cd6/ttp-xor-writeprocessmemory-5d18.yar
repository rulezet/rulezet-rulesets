rule TTP_XOR_WriteProcessMemory_5d18 {
  strings:
    $key_5d18 = { 0a 6a [2] 38 48 [2] 3e 7d [2] 10 7d [2] 2f 61 }

  condition:
    any of them
}