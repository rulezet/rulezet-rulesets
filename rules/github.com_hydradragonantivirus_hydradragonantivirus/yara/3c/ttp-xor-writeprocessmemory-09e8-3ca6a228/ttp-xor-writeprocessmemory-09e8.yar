rule TTP_XOR_WriteProcessMemory_09e8 {
  strings:
    $key_09e8 = { 5e 9a [2] 6c b8 [2] 6a 8d [2] 44 8d [2] 7b 91 }

  condition:
    any of them
}