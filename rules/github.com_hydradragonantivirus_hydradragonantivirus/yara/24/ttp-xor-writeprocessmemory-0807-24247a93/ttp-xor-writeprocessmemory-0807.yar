rule TTP_XOR_WriteProcessMemory_0807 {
  strings:
    $key_0807 = { 5f 75 [2] 6d 57 [2] 6b 62 [2] 45 62 [2] 7a 7e }

  condition:
    any of them
}