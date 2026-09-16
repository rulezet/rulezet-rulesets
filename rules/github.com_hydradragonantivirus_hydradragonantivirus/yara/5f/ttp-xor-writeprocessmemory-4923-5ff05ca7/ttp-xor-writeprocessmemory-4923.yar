rule TTP_XOR_WriteProcessMemory_4923 {
  strings:
    $key_4923 = { 1e 51 [2] 2c 73 [2] 2a 46 [2] 04 46 [2] 3b 5a }

  condition:
    any of them
}