rule TTP_XOR_WriteProcessMemory_6d54 {
  strings:
    $key_6d54 = { 3a 26 [2] 08 04 [2] 0e 31 [2] 20 31 [2] 1f 2d }

  condition:
    any of them
}