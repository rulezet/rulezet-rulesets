rule TTP_XOR_WriteProcessMemory_1227 {
  strings:
    $key_1227 = { 45 55 [2] 77 77 [2] 71 42 [2] 5f 42 [2] 60 5e }

  condition:
    any of them
}