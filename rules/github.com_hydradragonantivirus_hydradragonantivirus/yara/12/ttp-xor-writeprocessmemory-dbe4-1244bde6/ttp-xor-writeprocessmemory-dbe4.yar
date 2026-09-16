rule TTP_XOR_WriteProcessMemory_dbe4 {
  strings:
    $key_dbe4 = { 8c 96 [2] be b4 [2] b8 81 [2] 96 81 [2] a9 9d }

  condition:
    any of them
}