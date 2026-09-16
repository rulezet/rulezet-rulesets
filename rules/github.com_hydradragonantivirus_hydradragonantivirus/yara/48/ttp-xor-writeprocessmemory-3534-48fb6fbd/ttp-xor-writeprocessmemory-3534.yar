rule TTP_XOR_WriteProcessMemory_3534 {
  strings:
    $key_3534 = { 62 46 [2] 50 64 [2] 56 51 [2] 78 51 [2] 47 4d }

  condition:
    any of them
}