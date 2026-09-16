rule TTP_XOR_WriteProcessMemory_c907 {
  strings:
    $key_c907 = { 9e 75 [2] ac 57 [2] aa 62 [2] 84 62 [2] bb 7e }

  condition:
    any of them
}