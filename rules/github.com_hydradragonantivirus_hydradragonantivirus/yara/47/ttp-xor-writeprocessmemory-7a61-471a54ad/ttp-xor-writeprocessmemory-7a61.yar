rule TTP_XOR_WriteProcessMemory_7a61 {
  strings:
    $key_7a61 = { 2d 13 [2] 1f 31 [2] 19 04 [2] 37 04 [2] 08 18 }

  condition:
    any of them
}