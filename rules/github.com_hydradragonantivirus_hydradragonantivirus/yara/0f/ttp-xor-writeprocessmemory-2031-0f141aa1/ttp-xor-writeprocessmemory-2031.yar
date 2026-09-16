rule TTP_XOR_WriteProcessMemory_2031 {
  strings:
    $key_2031 = { 77 43 [2] 45 61 [2] 43 54 [2] 6d 54 [2] 52 48 }

  condition:
    any of them
}