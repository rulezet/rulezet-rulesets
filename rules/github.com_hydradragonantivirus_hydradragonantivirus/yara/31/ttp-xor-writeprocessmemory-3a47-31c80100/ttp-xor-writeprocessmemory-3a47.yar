rule TTP_XOR_WriteProcessMemory_3a47 {
  strings:
    $key_3a47 = { 6d 35 [2] 5f 17 [2] 59 22 [2] 77 22 [2] 48 3e }

  condition:
    any of them
}