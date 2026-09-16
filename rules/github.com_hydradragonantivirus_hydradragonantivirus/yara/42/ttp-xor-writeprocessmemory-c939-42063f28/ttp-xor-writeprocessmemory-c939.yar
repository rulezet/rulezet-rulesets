rule TTP_XOR_WriteProcessMemory_c939 {
  strings:
    $key_c939 = { 9e 4b [2] ac 69 [2] aa 5c [2] 84 5c [2] bb 40 }

  condition:
    any of them
}