rule TTP_XOR_WriteProcessMemory_2827 {
  strings:
    $key_2827 = { 7f 55 [2] 4d 77 [2] 4b 42 [2] 65 42 [2] 5a 5e }

  condition:
    any of them
}