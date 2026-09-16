rule TTP_XOR_WriteProcessMemory_7437 {
  strings:
    $key_7437 = { 23 45 [2] 11 67 [2] 17 52 [2] 39 52 [2] 06 4e }

  condition:
    any of them
}