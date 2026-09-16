rule TTP_XOR_WriteProcessMemory_1c93 {
  strings:
    $key_1c93 = { 4b e1 [2] 79 c3 [2] 7f f6 [2] 51 f6 [2] 6e ea }

  condition:
    any of them
}