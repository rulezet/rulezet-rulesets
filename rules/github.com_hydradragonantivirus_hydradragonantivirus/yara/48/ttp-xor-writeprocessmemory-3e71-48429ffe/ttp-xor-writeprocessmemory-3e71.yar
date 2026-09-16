rule TTP_XOR_WriteProcessMemory_3e71 {
  strings:
    $key_3e71 = { 69 03 [2] 5b 21 [2] 5d 14 [2] 73 14 [2] 4c 08 }

  condition:
    any of them
}