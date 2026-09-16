rule TTP_XOR_WriteProcessMemory_3965 {
  strings:
    $key_3965 = { 6e 17 [2] 5c 35 [2] 5a 00 [2] 74 00 [2] 4b 1c }

  condition:
    any of them
}