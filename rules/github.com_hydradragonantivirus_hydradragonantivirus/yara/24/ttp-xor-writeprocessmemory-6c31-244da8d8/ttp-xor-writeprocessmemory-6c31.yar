rule TTP_XOR_WriteProcessMemory_6c31 {
  strings:
    $key_6c31 = { 3b 43 [2] 09 61 [2] 0f 54 [2] 21 54 [2] 1e 48 }

  condition:
    any of them
}