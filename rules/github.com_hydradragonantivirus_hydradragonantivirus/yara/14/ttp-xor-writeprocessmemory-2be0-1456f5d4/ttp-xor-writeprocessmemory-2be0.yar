rule TTP_XOR_WriteProcessMemory_2be0 {
  strings:
    $key_2be0 = { 7c 92 [2] 4e b0 [2] 48 85 [2] 66 85 [2] 59 99 }

  condition:
    any of them
}