rule TTP_XOR_WriteProcessMemory_6186 {
  strings:
    $key_6186 = { 36 f4 [2] 04 d6 [2] 02 e3 [2] 2c e3 [2] 13 ff }

  condition:
    any of them
}