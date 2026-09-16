rule TTP_XOR_WriteProcessMemory_2de8 {
  strings:
    $key_2de8 = { 7a 9a [2] 48 b8 [2] 4e 8d [2] 60 8d [2] 5f 91 }

  condition:
    any of them
}