rule TTP_XOR_WriteProcessMemory_3c86 {
  strings:
    $key_3c86 = { 6b f4 [2] 59 d6 [2] 5f e3 [2] 71 e3 [2] 4e ff }

  condition:
    any of them
}