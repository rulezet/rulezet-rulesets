rule TTP_XOR_WriteProcessMemory_5437 {
  strings:
    $key_5437 = { 03 45 [2] 31 67 [2] 37 52 [2] 19 52 [2] 26 4e }

  condition:
    any of them
}