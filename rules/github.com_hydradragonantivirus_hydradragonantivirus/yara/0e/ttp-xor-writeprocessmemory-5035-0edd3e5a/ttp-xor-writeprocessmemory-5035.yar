rule TTP_XOR_WriteProcessMemory_5035 {
  strings:
    $key_5035 = { 07 47 [2] 35 65 [2] 33 50 [2] 1d 50 [2] 22 4c }

  condition:
    any of them
}