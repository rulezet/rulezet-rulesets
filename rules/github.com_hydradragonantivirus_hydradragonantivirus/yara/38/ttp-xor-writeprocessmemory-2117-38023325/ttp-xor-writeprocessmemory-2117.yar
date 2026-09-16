rule TTP_XOR_WriteProcessMemory_2117 {
  strings:
    $key_2117 = { 76 65 [2] 44 47 [2] 42 72 [2] 6c 72 [2] 53 6e }

  condition:
    any of them
}