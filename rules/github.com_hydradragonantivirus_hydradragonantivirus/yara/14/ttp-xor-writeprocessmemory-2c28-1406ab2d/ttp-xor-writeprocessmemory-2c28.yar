rule TTP_XOR_WriteProcessMemory_2c28 {
  strings:
    $key_2c28 = { 7b 5a [2] 49 78 [2] 4f 4d [2] 61 4d [2] 5e 51 }

  condition:
    any of them
}