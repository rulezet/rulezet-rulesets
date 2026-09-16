rule TTP_XOR_WriteProcessMemory_1e38 {
  strings:
    $key_1e38 = { 49 4a [2] 7b 68 [2] 7d 5d [2] 53 5d [2] 6c 41 }

  condition:
    any of them
}