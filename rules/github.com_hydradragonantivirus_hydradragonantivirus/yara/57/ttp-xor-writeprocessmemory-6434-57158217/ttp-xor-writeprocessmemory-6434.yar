rule TTP_XOR_WriteProcessMemory_6434 {
  strings:
    $key_6434 = { 33 46 [2] 01 64 [2] 07 51 [2] 29 51 [2] 16 4d }

  condition:
    any of them
}