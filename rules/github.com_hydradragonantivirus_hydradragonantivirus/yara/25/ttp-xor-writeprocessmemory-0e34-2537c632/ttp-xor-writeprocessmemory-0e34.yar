rule TTP_XOR_WriteProcessMemory_0e34 {
  strings:
    $key_0e34 = { 59 46 [2] 6b 64 [2] 6d 51 [2] 43 51 [2] 7c 4d }

  condition:
    any of them
}