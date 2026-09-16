rule TTP_XOR_WriteProcessMemory_db04 {
  strings:
    $key_db04 = { 8c 76 [2] be 54 [2] b8 61 [2] 96 61 [2] a9 7d }

  condition:
    any of them
}