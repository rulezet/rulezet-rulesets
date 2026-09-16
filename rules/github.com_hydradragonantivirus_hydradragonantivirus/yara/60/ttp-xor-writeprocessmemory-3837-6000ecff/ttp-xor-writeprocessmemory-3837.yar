rule TTP_XOR_WriteProcessMemory_3837 {
  strings:
    $key_3837 = { 6f 45 [2] 5d 67 [2] 5b 52 [2] 75 52 [2] 4a 4e }

  condition:
    any of them
}