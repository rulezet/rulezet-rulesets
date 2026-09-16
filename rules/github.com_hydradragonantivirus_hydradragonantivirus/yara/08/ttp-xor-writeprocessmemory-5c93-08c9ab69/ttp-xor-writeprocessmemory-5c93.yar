rule TTP_XOR_WriteProcessMemory_5c93 {
  strings:
    $key_5c93 = { 0b e1 [2] 39 c3 [2] 3f f6 [2] 11 f6 [2] 2e ea }

  condition:
    any of them
}