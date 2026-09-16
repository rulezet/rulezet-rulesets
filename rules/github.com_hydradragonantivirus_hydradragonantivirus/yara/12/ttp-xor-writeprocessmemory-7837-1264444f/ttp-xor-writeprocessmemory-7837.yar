rule TTP_XOR_WriteProcessMemory_7837 {
  strings:
    $key_7837 = { 2f 45 [2] 1d 67 [2] 1b 52 [2] 35 52 [2] 0a 4e }

  condition:
    any of them
}