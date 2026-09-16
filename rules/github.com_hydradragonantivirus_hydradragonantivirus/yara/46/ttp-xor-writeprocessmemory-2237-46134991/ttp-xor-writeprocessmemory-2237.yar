rule TTP_XOR_WriteProcessMemory_2237 {
  strings:
    $key_2237 = { 75 45 [2] 47 67 [2] 41 52 [2] 6f 52 [2] 50 4e }

  condition:
    any of them
}