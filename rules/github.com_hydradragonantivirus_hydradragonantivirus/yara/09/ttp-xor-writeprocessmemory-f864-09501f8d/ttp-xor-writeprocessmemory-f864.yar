rule TTP_XOR_WriteProcessMemory_f864 {
  strings:
    $key_f864 = { af 16 [2] 9d 34 [2] 9b 01 [2] b5 01 [2] 8a 1d }

  condition:
    any of them
}