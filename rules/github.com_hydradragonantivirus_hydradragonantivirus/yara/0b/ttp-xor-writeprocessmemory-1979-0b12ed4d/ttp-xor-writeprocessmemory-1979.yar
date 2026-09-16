rule TTP_XOR_WriteProcessMemory_1979 {
  strings:
    $key_1979 = { 4e 0b [2] 7c 29 [2] 7a 1c [2] 54 1c [2] 6b 00 }

  condition:
    any of them
}