rule TTP_XOR_WriteProcessMemory_3937 {
  strings:
    $key_3937 = { 6e 45 [2] 5c 67 [2] 5a 52 [2] 74 52 [2] 4b 4e }

  condition:
    any of them
}