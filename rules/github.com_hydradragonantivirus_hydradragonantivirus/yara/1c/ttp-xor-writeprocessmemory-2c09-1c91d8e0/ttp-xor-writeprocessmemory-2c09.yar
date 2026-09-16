rule TTP_XOR_WriteProcessMemory_2c09 {
  strings:
    $key_2c09 = { 7b 7b [2] 49 59 [2] 4f 6c [2] 61 6c [2] 5e 70 }

  condition:
    any of them
}