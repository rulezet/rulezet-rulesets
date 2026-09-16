rule TTP_XOR_WriteProcessMemory_0ec6 {
  strings:
    $key_0ec6 = { 59 b4 [2] 6b 96 [2] 6d a3 [2] 43 a3 [2] 7c bf }

  condition:
    any of them
}