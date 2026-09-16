rule TTP_XOR_WriteProcessMemory_79e8 {
  strings:
    $key_79e8 = { 2e 9a [2] 1c b8 [2] 1a 8d [2] 34 8d [2] 0b 91 }

  condition:
    any of them
}