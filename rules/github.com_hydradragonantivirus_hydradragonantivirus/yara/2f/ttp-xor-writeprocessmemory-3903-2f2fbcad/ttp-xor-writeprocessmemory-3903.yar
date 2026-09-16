rule TTP_XOR_WriteProcessMemory_3903 {
  strings:
    $key_3903 = { 6e 71 [2] 5c 53 [2] 5a 66 [2] 74 66 [2] 4b 7a }

  condition:
    any of them
}