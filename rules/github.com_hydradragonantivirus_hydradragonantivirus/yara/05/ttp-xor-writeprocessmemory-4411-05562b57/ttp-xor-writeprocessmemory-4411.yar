rule TTP_XOR_WriteProcessMemory_4411 {
  strings:
    $key_4411 = { 13 63 [2] 21 41 [2] 27 74 [2] 09 74 [2] 36 68 }

  condition:
    any of them
}