rule TTP_XOR_WriteProcessMemory_4e61 {
  strings:
    $key_4e61 = { 19 13 [2] 2b 31 [2] 2d 04 [2] 03 04 [2] 3c 18 }

  condition:
    any of them
}