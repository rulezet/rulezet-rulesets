rule TTP_XOR_WriteProcessMemory_4438 {
  strings:
    $key_4438 = { 13 4a [2] 21 68 [2] 27 5d [2] 09 5d [2] 36 41 }

  condition:
    any of them
}