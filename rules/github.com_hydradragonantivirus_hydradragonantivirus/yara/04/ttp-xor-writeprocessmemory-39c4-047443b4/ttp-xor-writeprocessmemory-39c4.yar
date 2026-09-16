rule TTP_XOR_WriteProcessMemory_39c4 {
  strings:
    $key_39c4 = { 6e b6 [2] 5c 94 [2] 5a a1 [2] 74 a1 [2] 4b bd }

  condition:
    any of them
}