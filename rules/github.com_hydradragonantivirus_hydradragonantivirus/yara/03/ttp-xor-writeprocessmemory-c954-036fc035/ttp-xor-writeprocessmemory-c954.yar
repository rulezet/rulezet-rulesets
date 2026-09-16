rule TTP_XOR_WriteProcessMemory_c954 {
  strings:
    $key_c954 = { 9e 26 [2] ac 04 [2] aa 31 [2] 84 31 [2] bb 2d }

  condition:
    any of them
}