rule TTP_XOR_WriteProcessMemory_c947 {
  strings:
    $key_c947 = { 9e 35 [2] ac 17 [2] aa 22 [2] 84 22 [2] bb 3e }

  condition:
    any of them
}