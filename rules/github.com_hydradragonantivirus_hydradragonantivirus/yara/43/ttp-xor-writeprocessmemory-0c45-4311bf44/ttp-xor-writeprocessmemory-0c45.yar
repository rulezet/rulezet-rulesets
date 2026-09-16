rule TTP_XOR_WriteProcessMemory_0c45 {
  strings:
    $key_0c45 = { 5b 37 [2] 69 15 [2] 6f 20 [2] 41 20 [2] 7e 3c }

  condition:
    any of them
}