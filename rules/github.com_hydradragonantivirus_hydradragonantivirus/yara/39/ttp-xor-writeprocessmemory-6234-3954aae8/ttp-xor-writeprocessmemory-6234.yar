rule TTP_XOR_WriteProcessMemory_6234 {
  strings:
    $key_6234 = { 35 46 [2] 07 64 [2] 01 51 [2] 2f 51 [2] 10 4d }

  condition:
    any of them
}