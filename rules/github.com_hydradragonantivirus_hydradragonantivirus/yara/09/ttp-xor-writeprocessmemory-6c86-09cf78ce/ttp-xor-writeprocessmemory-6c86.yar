rule TTP_XOR_WriteProcessMemory_6c86 {
  strings:
    $key_6c86 = { 3b f4 [2] 09 d6 [2] 0f e3 [2] 21 e3 [2] 1e ff }

  condition:
    any of them
}