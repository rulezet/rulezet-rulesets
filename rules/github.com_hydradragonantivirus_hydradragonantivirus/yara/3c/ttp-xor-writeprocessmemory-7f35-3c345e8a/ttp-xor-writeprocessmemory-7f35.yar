rule TTP_XOR_WriteProcessMemory_7f35 {
  strings:
    $key_7f35 = { 28 47 [2] 1a 65 [2] 1c 50 [2] 32 50 [2] 0d 4c }

  condition:
    any of them
}