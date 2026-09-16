rule TTP_XOR_WriteProcessMemory_2b67 {
  strings:
    $key_2b67 = { 7c 15 [2] 4e 37 [2] 48 02 [2] 66 02 [2] 59 1e }

  condition:
    any of them
}