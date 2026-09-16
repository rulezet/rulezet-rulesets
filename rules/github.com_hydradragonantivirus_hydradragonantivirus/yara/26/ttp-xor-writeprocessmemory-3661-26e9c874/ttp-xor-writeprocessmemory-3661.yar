rule TTP_XOR_WriteProcessMemory_3661 {
  strings:
    $key_3661 = { 61 13 [2] 53 31 [2] 55 04 [2] 7b 04 [2] 44 18 }

  condition:
    any of them
}