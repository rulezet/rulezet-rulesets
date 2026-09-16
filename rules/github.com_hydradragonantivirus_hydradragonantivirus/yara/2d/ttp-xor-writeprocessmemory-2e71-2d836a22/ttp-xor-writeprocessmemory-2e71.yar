rule TTP_XOR_WriteProcessMemory_2e71 {
  strings:
    $key_2e71 = { 79 03 [2] 4b 21 [2] 4d 14 [2] 63 14 [2] 5c 08 }

  condition:
    any of them
}