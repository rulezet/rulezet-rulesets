rule TTP_XOR_WriteProcessMemory_2c01 {
  strings:
    $key_2c01 = { 7b 73 [2] 49 51 [2] 4f 64 [2] 61 64 [2] 5e 78 }

  condition:
    any of them
}