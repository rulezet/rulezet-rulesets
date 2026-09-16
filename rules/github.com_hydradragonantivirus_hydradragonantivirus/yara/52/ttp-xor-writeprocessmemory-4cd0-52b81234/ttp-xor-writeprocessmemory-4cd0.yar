rule TTP_XOR_WriteProcessMemory_4cd0 {
  strings:
    $key_4cd0 = { 1b a2 [2] 29 80 [2] 2f b5 [2] 01 b5 [2] 3e a9 }

  condition:
    any of them
}