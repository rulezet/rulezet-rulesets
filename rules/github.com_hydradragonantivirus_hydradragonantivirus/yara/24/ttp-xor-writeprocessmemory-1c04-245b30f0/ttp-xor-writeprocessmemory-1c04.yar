rule TTP_XOR_WriteProcessMemory_1c04 {
  strings:
    $key_1c04 = { 4b 76 [2] 79 54 [2] 7f 61 [2] 51 61 [2] 6e 7d }

  condition:
    any of them
}