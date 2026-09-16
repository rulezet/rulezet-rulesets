rule TTP_XOR_WriteProcessMemory_2a11 {
  strings:
    $key_2a11 = { 7d 63 [2] 4f 41 [2] 49 74 [2] 67 74 [2] 58 68 }

  condition:
    any of them
}