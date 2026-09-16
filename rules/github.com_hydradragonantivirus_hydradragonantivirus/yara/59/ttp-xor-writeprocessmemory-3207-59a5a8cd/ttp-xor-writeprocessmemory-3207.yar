rule TTP_XOR_WriteProcessMemory_3207 {
  strings:
    $key_3207 = { 65 75 [2] 57 57 [2] 51 62 [2] 7f 62 [2] 40 7e }

  condition:
    any of them
}