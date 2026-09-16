rule TTP_XOR_WriteProcessMemory_7234 {
  strings:
    $key_7234 = { 25 46 [2] 17 64 [2] 11 51 [2] 3f 51 [2] 00 4d }

  condition:
    any of them
}