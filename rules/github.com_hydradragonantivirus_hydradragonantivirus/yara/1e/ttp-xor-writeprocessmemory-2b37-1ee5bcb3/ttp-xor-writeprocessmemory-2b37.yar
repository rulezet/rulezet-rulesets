rule TTP_XOR_WriteProcessMemory_2b37 {
  strings:
    $key_2b37 = { 7c 45 [2] 4e 67 [2] 48 52 [2] 66 52 [2] 59 4e }

  condition:
    any of them
}