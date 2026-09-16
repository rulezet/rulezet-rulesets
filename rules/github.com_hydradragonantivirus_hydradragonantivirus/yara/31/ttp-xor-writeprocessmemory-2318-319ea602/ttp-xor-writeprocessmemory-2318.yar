rule TTP_XOR_WriteProcessMemory_2318 {
  strings:
    $key_2318 = { 74 6a [2] 46 48 [2] 40 7d [2] 6e 7d [2] 51 61 }

  condition:
    any of them
}