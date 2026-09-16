rule TTP_XOR_WriteProcessMemory_0607 {
  strings:
    $key_0607 = { 51 75 [2] 63 57 [2] 65 62 [2] 4b 62 [2] 74 7e }

  condition:
    any of them
}