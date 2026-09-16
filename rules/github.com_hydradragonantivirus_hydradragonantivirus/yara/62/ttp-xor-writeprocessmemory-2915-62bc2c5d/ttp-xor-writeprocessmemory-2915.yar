rule TTP_XOR_WriteProcessMemory_2915 {
  strings:
    $key_2915 = { 7e 67 [2] 4c 45 [2] 4a 70 [2] 64 70 [2] 5b 6c }

  condition:
    any of them
}