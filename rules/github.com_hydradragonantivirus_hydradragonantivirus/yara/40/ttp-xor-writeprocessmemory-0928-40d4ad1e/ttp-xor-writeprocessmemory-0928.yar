rule TTP_XOR_WriteProcessMemory_0928 {
  strings:
    $key_0928 = { 5e 5a [2] 6c 78 [2] 6a 4d [2] 44 4d [2] 7b 51 }

  condition:
    any of them
}