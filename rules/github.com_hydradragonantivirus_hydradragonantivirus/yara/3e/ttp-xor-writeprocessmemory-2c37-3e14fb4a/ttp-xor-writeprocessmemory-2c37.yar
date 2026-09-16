rule TTP_XOR_WriteProcessMemory_2c37 {
  strings:
    $key_2c37 = { 7b 45 [2] 49 67 [2] 4f 52 [2] 61 52 [2] 5e 4e }

  condition:
    any of them
}