rule TTP_XOR_WriteProcessMemory_0020 {
  strings:
    $key_0020 = { 57 52 [2] 65 70 [2] 63 45 [2] 4d 45 [2] 72 59 }

  condition:
    any of them
}