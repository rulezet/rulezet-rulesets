rule TTP_XOR_WriteProcessMemory_6b31 {
  strings:
    $key_6b31 = { 3c 43 [2] 0e 61 [2] 08 54 [2] 26 54 [2] 19 48 }

  condition:
    any of them
}