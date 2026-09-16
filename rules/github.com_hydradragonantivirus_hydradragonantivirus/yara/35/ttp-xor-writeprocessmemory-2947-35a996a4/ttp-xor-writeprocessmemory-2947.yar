rule TTP_XOR_WriteProcessMemory_2947 {
  strings:
    $key_2947 = { 7e 35 [2] 4c 17 [2] 4a 22 [2] 64 22 [2] 5b 3e }

  condition:
    any of them
}