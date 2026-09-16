rule TTP_XOR_WriteProcessMemory_0037 {
  strings:
    $key_0037 = { 57 45 [2] 65 67 [2] 63 52 [2] 4d 52 [2] 72 4e }

  condition:
    any of them
}