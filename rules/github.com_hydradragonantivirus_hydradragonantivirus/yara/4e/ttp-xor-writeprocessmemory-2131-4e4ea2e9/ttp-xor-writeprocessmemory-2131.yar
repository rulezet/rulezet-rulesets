rule TTP_XOR_WriteProcessMemory_2131 {
  strings:
    $key_2131 = { 76 43 [2] 44 61 [2] 42 54 [2] 6c 54 [2] 53 48 }

  condition:
    any of them
}