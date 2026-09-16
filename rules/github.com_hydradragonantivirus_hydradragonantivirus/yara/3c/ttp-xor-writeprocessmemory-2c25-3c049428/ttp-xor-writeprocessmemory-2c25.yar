rule TTP_XOR_WriteProcessMemory_2c25 {
  strings:
    $key_2c25 = { 7b 57 [2] 49 75 [2] 4f 40 [2] 61 40 [2] 5e 5c }

  condition:
    any of them
}