rule TTP_XOR_WriteProcessMemory_68ed {
  strings:
    $key_68ed = { 3f 9f [2] 0d bd [2] 0b 88 [2] 25 88 [2] 1a 94 }

  condition:
    any of them
}