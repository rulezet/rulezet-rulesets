rule TTP_XOR_WriteProcessMemory_2c20 {
  strings:
    $key_2c20 = { 7b 52 [2] 49 70 [2] 4f 45 [2] 61 45 [2] 5e 59 }

  condition:
    any of them
}