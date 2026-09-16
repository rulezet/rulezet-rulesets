rule TTP_XOR_WriteProcessMemory_0237 {
  strings:
    $key_0237 = { 55 45 [2] 67 67 [2] 61 52 [2] 4f 52 [2] 70 4e }

  condition:
    any of them
}