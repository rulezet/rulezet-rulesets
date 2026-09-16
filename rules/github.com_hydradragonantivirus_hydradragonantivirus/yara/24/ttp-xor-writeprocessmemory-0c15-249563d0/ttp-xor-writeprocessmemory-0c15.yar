rule TTP_XOR_WriteProcessMemory_0c15 {
  strings:
    $key_0c15 = { 5b 67 [2] 69 45 [2] 6f 70 [2] 41 70 [2] 7e 6c }

  condition:
    any of them
}