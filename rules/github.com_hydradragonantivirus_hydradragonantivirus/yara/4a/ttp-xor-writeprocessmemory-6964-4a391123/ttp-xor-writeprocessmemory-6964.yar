rule TTP_XOR_WriteProcessMemory_6964 {
  strings:
    $key_6964 = { 3e 16 [2] 0c 34 [2] 0a 01 [2] 24 01 [2] 1b 1d }

  condition:
    any of them
}