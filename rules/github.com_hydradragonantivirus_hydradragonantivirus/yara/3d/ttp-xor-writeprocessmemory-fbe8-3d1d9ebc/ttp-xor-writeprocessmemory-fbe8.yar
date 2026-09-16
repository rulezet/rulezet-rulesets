rule TTP_XOR_WriteProcessMemory_fbe8 {
  strings:
    $key_fbe8 = { ac 9a [2] 9e b8 [2] 98 8d [2] b6 8d [2] 89 91 }

  condition:
    any of them
}