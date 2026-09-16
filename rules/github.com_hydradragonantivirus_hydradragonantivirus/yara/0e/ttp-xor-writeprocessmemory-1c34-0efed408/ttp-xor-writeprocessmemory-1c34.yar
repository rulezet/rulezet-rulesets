rule TTP_XOR_WriteProcessMemory_1c34 {
  strings:
    $key_1c34 = { 4b 46 [2] 79 64 [2] 7f 51 [2] 51 51 [2] 6e 4d }

  condition:
    any of them
}