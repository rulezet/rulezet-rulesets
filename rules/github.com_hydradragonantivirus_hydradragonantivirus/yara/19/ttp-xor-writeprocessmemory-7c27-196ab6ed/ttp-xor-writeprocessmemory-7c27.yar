rule TTP_XOR_WriteProcessMemory_7c27 {
  strings:
    $key_7c27 = { 2b 55 [2] 19 77 [2] 1f 42 [2] 31 42 [2] 0e 5e }

  condition:
    any of them
}