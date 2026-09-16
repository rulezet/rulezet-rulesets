rule TTP_XOR_WriteProcessMemory_0a47 {
  strings:
    $key_0a47 = { 5d 35 [2] 6f 17 [2] 69 22 [2] 47 22 [2] 78 3e }

  condition:
    any of them
}