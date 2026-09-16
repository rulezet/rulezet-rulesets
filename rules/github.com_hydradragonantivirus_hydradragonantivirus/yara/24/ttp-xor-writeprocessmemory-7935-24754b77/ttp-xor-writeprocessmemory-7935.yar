rule TTP_XOR_WriteProcessMemory_7935 {
  strings:
    $key_7935 = { 2e 47 [2] 1c 65 [2] 1a 50 [2] 34 50 [2] 0b 4c }

  condition:
    any of them
}