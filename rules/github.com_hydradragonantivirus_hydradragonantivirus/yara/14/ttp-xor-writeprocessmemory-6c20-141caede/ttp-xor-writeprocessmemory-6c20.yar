rule TTP_XOR_WriteProcessMemory_6c20 {
  strings:
    $key_6c20 = { 3b 52 [2] 09 70 [2] 0f 45 [2] 21 45 [2] 1e 59 }

  condition:
    any of them
}