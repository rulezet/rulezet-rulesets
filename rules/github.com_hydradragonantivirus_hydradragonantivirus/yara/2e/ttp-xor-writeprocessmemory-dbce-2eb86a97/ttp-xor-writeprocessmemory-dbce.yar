rule TTP_XOR_WriteProcessMemory_dbce {
  strings:
    $key_dbce = { 8c bc [2] be 9e [2] b8 ab [2] 96 ab [2] a9 b7 }

  condition:
    any of them
}