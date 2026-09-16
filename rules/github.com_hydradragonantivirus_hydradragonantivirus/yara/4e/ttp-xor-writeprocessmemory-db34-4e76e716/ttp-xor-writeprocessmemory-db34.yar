rule TTP_XOR_WriteProcessMemory_db34 {
  strings:
    $key_db34 = { 8c 46 [2] be 64 [2] b8 51 [2] 96 51 [2] a9 4d }

  condition:
    any of them
}