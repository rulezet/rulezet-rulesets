rule TTP_XOR_WriteProcessMemory_1911 {
  strings:
    $key_1911 = { 4e 63 [2] 7c 41 [2] 7a 74 [2] 54 74 [2] 6b 68 }

  condition:
    any of them
}