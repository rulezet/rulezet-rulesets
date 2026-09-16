rule TTP_XOR_WriteProcessMemory_0875 {
  strings:
    $key_0875 = { 5f 07 [2] 6d 25 [2] 6b 10 [2] 45 10 [2] 7a 0c }

  condition:
    any of them
}