rule TTP_XOR_WriteProcessMemory_7227 {
  strings:
    $key_7227 = { 25 55 [2] 17 77 [2] 11 42 [2] 3f 42 [2] 00 5e }

  condition:
    any of them
}