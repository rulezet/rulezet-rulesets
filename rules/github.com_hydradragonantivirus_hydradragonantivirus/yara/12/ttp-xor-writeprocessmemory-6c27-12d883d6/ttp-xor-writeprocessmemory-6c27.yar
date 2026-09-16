rule TTP_XOR_WriteProcessMemory_6c27 {
  strings:
    $key_6c27 = { 3b 55 [2] 09 77 [2] 0f 42 [2] 21 42 [2] 1e 5e }

  condition:
    any of them
}