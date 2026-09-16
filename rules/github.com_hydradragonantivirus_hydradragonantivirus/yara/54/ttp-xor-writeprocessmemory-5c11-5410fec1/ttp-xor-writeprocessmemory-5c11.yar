rule TTP_XOR_WriteProcessMemory_5c11 {
  strings:
    $key_5c11 = { 0b 63 [2] 39 41 [2] 3f 74 [2] 11 74 [2] 2e 68 }

  condition:
    any of them
}