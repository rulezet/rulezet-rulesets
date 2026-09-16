rule TTP_XOR_WriteProcessMemory_1c85 {
  strings:
    $key_1c85 = { 4b f7 [2] 79 d5 [2] 7f e0 [2] 51 e0 [2] 6e fc }

  condition:
    any of them
}