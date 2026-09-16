rule TTP_XOR_WriteProcessMemory_28c6 {
  strings:
    $key_28c6 = { 7f b4 [2] 4d 96 [2] 4b a3 [2] 65 a3 [2] 5a bf }

  condition:
    any of them
}