rule TTP_XOR_WriteProcessMemory_0925 {
  strings:
    $key_0925 = { 5e 57 [2] 6c 75 [2] 6a 40 [2] 44 40 [2] 7b 5c }

  condition:
    any of them
}