rule TTP_XOR_WriteProcessMemory_0c27 {
  strings:
    $key_0c27 = { 5b 55 [2] 69 77 [2] 6f 42 [2] 41 42 [2] 7e 5e }

  condition:
    any of them
}