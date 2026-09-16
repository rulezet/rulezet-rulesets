rule TTP_XOR_WriteProcessMemory_0935 {
  strings:
    $key_0935 = { 5e 47 [2] 6c 65 [2] 6a 50 [2] 44 50 [2] 7b 4c }

  condition:
    any of them
}