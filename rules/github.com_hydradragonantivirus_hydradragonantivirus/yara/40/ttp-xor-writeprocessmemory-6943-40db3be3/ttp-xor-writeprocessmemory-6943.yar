rule TTP_XOR_WriteProcessMemory_6943 {
  strings:
    $key_6943 = { 3e 31 [2] 0c 13 [2] 0a 26 [2] 24 26 [2] 1b 3a }

  condition:
    any of them
}