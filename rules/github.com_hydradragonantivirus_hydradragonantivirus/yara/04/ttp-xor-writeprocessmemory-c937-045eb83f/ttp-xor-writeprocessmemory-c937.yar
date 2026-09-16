rule TTP_XOR_WriteProcessMemory_c937 {
  strings:
    $key_c937 = { 9e 45 [2] ac 67 [2] aa 52 [2] 84 52 [2] bb 4e }

  condition:
    any of them
}