rule TTP_XOR_WriteProcessMemory_7c93 {
  strings:
    $key_7c93 = { 2b e1 [2] 19 c3 [2] 1f f6 [2] 31 f6 [2] 0e ea }

  condition:
    any of them
}