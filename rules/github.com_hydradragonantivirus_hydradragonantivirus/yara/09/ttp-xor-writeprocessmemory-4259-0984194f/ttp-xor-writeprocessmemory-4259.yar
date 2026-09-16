rule TTP_XOR_WriteProcessMemory_4259 {
  strings:
    $key_4259 = { 15 2b [2] 27 09 [2] 21 3c [2] 0f 3c [2] 30 20 }

  condition:
    any of them
}