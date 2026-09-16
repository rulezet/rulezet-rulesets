rule TTP_XOR_WriteProcessMemory_4c20 {
  strings:
    $key_4c20 = { 1b 52 [2] 29 70 [2] 2f 45 [2] 01 45 [2] 3e 59 }

  condition:
    any of them
}