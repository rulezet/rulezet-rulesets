rule TTP_XOR_WriteProcessMemory_2964 {
  strings:
    $key_2964 = { 7e 16 [2] 4c 34 [2] 4a 01 [2] 64 01 [2] 5b 1d }

  condition:
    any of them
}