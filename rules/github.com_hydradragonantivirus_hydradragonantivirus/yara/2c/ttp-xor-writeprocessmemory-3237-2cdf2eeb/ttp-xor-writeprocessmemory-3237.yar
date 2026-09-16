rule TTP_XOR_WriteProcessMemory_3237 {
  strings:
    $key_3237 = { 65 45 [2] 57 67 [2] 51 52 [2] 7f 52 [2] 40 4e }

  condition:
    any of them
}