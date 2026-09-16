rule TTP_XOR_WriteProcessMemory_3925 {
  strings:
    $key_3925 = { 6e 57 [2] 5c 75 [2] 5a 40 [2] 74 40 [2] 4b 5c }

  condition:
    any of them
}