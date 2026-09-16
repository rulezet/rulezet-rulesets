rule TTP_XOR_WriteProcessMemory_5a37 {
  strings:
    $key_5a37 = { 0d 45 [2] 3f 67 [2] 39 52 [2] 17 52 [2] 28 4e }

  condition:
    any of them
}