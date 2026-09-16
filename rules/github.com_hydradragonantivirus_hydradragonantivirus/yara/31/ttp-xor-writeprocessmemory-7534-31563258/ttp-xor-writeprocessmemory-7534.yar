rule TTP_XOR_WriteProcessMemory_7534 {
  strings:
    $key_7534 = { 22 46 [2] 10 64 [2] 16 51 [2] 38 51 [2] 07 4d }

  condition:
    any of them
}