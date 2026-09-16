rule TTP_XOR_WriteProcessMemory_2e38 {
  strings:
    $key_2e38 = { 79 4a [2] 4b 68 [2] 4d 5d [2] 63 5d [2] 5c 41 }

  condition:
    any of them
}