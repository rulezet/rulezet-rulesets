rule TTP_XOR_WriteProcessMemory_6954 {
  strings:
    $key_6954 = { 3e 26 [2] 0c 04 [2] 0a 31 [2] 24 31 [2] 1b 2d }

  condition:
    any of them
}