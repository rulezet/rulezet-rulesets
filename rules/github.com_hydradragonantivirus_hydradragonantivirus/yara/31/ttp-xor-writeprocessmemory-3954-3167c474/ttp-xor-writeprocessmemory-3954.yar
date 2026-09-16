rule TTP_XOR_WriteProcessMemory_3954 {
  strings:
    $key_3954 = { 6e 26 [2] 5c 04 [2] 5a 31 [2] 74 31 [2] 4b 2d }

  condition:
    any of them
}