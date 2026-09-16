rule TTP_XOR_WriteProcessMemory_4935 {
  strings:
    $key_4935 = { 1e 47 [2] 2c 65 [2] 2a 50 [2] 04 50 [2] 3b 4c }

  condition:
    any of them
}