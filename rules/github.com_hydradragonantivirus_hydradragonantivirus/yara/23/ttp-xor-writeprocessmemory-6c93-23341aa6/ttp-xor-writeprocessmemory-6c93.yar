rule TTP_XOR_WriteProcessMemory_6c93 {
  strings:
    $key_6c93 = { 3b e1 [2] 09 c3 [2] 0f f6 [2] 21 f6 [2] 1e ea }

  condition:
    any of them
}