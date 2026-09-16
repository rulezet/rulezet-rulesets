rule TTP_XOR_WriteProcessMemory_68c6 {
  strings:
    $key_68c6 = { 3f b4 [2] 0d 96 [2] 0b a3 [2] 25 a3 [2] 1a bf }

  condition:
    any of them
}