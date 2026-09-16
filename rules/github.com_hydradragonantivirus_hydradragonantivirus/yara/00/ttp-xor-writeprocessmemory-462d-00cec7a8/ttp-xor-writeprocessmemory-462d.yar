rule TTP_XOR_WriteProcessMemory_462d {
  strings:
    $key_462d = { 11 5f [2] 23 7d [2] 25 48 [2] 0b 48 [2] 34 54 }

  condition:
    any of them
}