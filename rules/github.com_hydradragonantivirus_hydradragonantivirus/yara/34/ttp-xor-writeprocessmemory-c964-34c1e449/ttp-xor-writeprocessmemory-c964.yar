rule TTP_XOR_WriteProcessMemory_c964 {
  strings:
    $key_c964 = { 9e 16 [2] ac 34 [2] aa 01 [2] 84 01 [2] bb 1d }

  condition:
    any of them
}