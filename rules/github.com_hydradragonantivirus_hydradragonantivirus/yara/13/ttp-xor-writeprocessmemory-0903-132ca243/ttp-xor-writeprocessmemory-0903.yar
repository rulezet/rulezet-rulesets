rule TTP_XOR_WriteProcessMemory_0903 {
  strings:
    $key_0903 = { 5e 71 [2] 6c 53 [2] 6a 66 [2] 44 66 [2] 7b 7a }

  condition:
    any of them
}