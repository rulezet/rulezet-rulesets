rule TTP_XOR_WriteProcessMemory_3c27 {
  strings:
    $key_3c27 = { 6b 55 [2] 59 77 [2] 5f 42 [2] 71 42 [2] 4e 5e }

  condition:
    any of them
}