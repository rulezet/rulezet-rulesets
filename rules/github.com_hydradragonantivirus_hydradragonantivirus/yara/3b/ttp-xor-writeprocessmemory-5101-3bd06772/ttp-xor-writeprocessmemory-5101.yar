rule TTP_XOR_WriteProcessMemory_5101 {
  strings:
    $key_5101 = { 06 73 [2] 34 51 [2] 32 64 [2] 1c 64 [2] 23 78 }

  condition:
    any of them
}