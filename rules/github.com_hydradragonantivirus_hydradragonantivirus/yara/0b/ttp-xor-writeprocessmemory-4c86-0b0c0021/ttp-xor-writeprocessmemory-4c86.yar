rule TTP_XOR_WriteProcessMemory_4c86 {
  strings:
    $key_4c86 = { 1b f4 [2] 29 d6 [2] 2f e3 [2] 01 e3 [2] 3e ff }

  condition:
    any of them
}