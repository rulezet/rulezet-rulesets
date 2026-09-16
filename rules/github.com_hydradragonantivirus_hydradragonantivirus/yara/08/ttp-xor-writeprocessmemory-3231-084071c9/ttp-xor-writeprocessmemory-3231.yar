rule TTP_XOR_WriteProcessMemory_3231 {
  strings:
    $key_3231 = { 65 43 [2] 57 61 [2] 51 54 [2] 7f 54 [2] 40 48 }

  condition:
    any of them
}