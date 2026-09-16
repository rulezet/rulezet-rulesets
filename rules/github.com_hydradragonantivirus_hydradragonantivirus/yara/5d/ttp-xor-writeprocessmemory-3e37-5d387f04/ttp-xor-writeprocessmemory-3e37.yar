rule TTP_XOR_WriteProcessMemory_3e37 {
  strings:
    $key_3e37 = { 69 45 [2] 5b 67 [2] 5d 52 [2] 73 52 [2] 4c 4e }

  condition:
    any of them
}