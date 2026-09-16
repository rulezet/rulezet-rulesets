rule TTP_XOR_WriteProcessMemory_2161 {
  strings:
    $key_2161 = { 76 13 [2] 44 31 [2] 42 04 [2] 6c 04 [2] 53 18 }

  condition:
    any of them
}