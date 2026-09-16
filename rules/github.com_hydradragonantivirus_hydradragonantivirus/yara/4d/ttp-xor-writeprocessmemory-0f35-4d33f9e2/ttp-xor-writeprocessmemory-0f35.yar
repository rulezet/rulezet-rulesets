rule TTP_XOR_WriteProcessMemory_0f35 {
  strings:
    $key_0f35 = { 58 47 [2] 6a 65 [2] 6c 50 [2] 42 50 [2] 7d 4c }

  condition:
    any of them
}