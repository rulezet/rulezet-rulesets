rule TTP_XOR_WriteProcessMemory_38c6 {
  strings:
    $key_38c6 = { 6f b4 [2] 5d 96 [2] 5b a3 [2] 75 a3 [2] 4a bf }

  condition:
    any of them
}