rule TTP_XOR_WriteProcessMemory_2b54 {
  strings:
    $key_2b54 = { 7c 26 [2] 4e 04 [2] 48 31 [2] 66 31 [2] 59 2d }

  condition:
    any of them
}