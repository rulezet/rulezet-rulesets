rule TTP_XOR_WriteProcessMemory_7c31 {
  strings:
    $key_7c31 = { 2b 43 [2] 19 61 [2] 1f 54 [2] 31 54 [2] 0e 48 }

  condition:
    any of them
}