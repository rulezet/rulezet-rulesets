rule TTP_XOR_WriteProcessMemory_1b32 {
  strings:
    $key_1b32 = { 4c 40 [2] 7e 62 [2] 78 57 [2] 56 57 [2] 69 4b }

  condition:
    any of them
}