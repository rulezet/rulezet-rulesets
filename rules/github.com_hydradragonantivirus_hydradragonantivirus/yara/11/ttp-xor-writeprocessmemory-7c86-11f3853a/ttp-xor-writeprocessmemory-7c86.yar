rule TTP_XOR_WriteProcessMemory_7c86 {
  strings:
    $key_7c86 = { 2b f4 [2] 19 d6 [2] 1f e3 [2] 31 e3 [2] 0e ff }

  condition:
    any of them
}