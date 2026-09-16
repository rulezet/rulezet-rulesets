rule TTP_XOR_WriteProcessMemory_093d {
  strings:
    $key_093d = { 5e 4f [2] 6c 6d [2] 6a 58 [2] 44 58 [2] 7b 44 }

  condition:
    any of them
}