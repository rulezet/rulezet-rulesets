rule TTP_XOR_WriteProcessMemory_7b53 {
  strings:
    $key_7b53 = { 2c 21 [2] 1e 03 [2] 18 36 [2] 36 36 [2] 09 2a }

  condition:
    any of them
}