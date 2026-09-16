rule TTP_XOR_WriteProcessMemory_fa27 {
  strings:
    $key_fa27 = { ad 55 [2] 9f 77 [2] 99 42 [2] b7 42 [2] 88 5e }

  condition:
    any of them
}