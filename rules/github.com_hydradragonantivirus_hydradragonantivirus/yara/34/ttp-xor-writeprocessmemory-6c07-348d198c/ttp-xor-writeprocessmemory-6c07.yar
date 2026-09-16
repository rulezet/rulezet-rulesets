rule TTP_XOR_WriteProcessMemory_6c07 {
  strings:
    $key_6c07 = { 3b 75 [2] 09 57 [2] 0f 62 [2] 21 62 [2] 1e 7e }

  condition:
    any of them
}