rule TTP_XOR_WriteProcessMemory_2c17 {
  strings:
    $key_2c17 = { 7b 65 [2] 49 47 [2] 4f 72 [2] 61 72 [2] 5e 6e }

  condition:
    any of them
}