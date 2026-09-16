rule TTP_XOR_WriteProcessMemory_7807 {
  strings:
    $key_7807 = { 2f 75 [2] 1d 57 [2] 1b 62 [2] 35 62 [2] 0a 7e }

  condition:
    any of them
}