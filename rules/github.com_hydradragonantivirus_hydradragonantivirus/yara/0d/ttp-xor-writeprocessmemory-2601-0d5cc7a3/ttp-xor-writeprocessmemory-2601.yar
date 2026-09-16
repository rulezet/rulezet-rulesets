rule TTP_XOR_WriteProcessMemory_2601 {
  strings:
    $key_2601 = { 71 73 [2] 43 51 [2] 45 64 [2] 6b 64 [2] 54 78 }

  condition:
    any of them
}