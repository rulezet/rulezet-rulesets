rule TTP_XOR_WriteProcessMemory_6786 {
  strings:
    $key_6786 = { 30 f4 [2] 02 d6 [2] 04 e3 [2] 2a e3 [2] 15 ff }

  condition:
    any of them
}