rule TTP_XOR_WriteProcessMemory_6c71 {
  strings:
    $key_6c71 = { 3b 03 [2] 09 21 [2] 0f 14 [2] 21 14 [2] 1e 08 }

  condition:
    any of them
}