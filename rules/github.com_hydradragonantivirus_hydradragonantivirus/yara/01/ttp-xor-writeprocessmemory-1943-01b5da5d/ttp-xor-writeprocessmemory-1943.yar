rule TTP_XOR_WriteProcessMemory_1943 {
  strings:
    $key_1943 = { 4e 31 [2] 7c 13 [2] 7a 26 [2] 54 26 [2] 6b 3a }

  condition:
    any of them
}