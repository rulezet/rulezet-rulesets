rule TTP_XOR_WriteProcessMemory_7443 {
  strings:
    $key_7443 = { 23 31 [2] 11 13 [2] 17 26 [2] 39 26 [2] 06 3a }

  condition:
    any of them
}