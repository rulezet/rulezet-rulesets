rule TTP_XOR_WriteProcessMemory_69e8 {
  strings:
    $key_69e8 = { 3e 9a [2] 0c b8 [2] 0a 8d [2] 24 8d [2] 1b 91 }

  condition:
    any of them
}