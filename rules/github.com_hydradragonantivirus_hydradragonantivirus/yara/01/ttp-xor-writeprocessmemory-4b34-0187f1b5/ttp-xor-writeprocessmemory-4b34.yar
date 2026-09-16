rule TTP_XOR_WriteProcessMemory_4b34 {
  strings:
    $key_4b34 = { 1c 46 [2] 2e 64 [2] 28 51 [2] 06 51 [2] 39 4d }

  condition:
    any of them
}