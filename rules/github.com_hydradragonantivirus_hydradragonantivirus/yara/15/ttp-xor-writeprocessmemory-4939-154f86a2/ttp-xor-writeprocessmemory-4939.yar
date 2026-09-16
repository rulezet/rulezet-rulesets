rule TTP_XOR_WriteProcessMemory_4939 {
  strings:
    $key_4939 = { 1e 4b [2] 2c 69 [2] 2a 5c [2] 04 5c [2] 3b 40 }

  condition:
    any of them
}