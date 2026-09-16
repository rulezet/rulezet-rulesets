rule TTP_XOR_WriteProcessMemory_0911 {
  strings:
    $key_0911 = { 5e 63 [2] 6c 41 [2] 6a 74 [2] 44 74 [2] 7b 68 }

  condition:
    any of them
}