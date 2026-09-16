rule TTP_XOR_WriteProcessMemory_2338 {
  strings:
    $key_2338 = { 74 4a [2] 46 68 [2] 40 5d [2] 6e 5d [2] 51 41 }

  condition:
    any of them
}