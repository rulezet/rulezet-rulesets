rule TTP_XOR_WriteProcessMemory_0825 {
  strings:
    $key_0825 = { 5f 57 [2] 6d 75 [2] 6b 40 [2] 45 40 [2] 7a 5c }

  condition:
    any of them
}