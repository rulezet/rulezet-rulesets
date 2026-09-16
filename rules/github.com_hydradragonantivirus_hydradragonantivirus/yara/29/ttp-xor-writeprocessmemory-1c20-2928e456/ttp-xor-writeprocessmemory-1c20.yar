rule TTP_XOR_WriteProcessMemory_1c20 {
  strings:
    $key_1c20 = { 4b 52 [2] 79 70 [2] 7f 45 [2] 51 45 [2] 6e 59 }

  condition:
    any of them
}