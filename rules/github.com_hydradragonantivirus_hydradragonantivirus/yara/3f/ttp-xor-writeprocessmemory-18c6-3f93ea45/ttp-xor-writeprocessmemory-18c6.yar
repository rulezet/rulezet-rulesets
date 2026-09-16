rule TTP_XOR_WriteProcessMemory_18c6 {
  strings:
    $key_18c6 = { 4f b4 [2] 7d 96 [2] 7b a3 [2] 55 a3 [2] 6a bf }

  condition:
    any of them
}