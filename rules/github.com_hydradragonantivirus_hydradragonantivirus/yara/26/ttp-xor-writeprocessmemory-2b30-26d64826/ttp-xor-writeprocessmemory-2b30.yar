rule TTP_XOR_WriteProcessMemory_2b30 {
  strings:
    $key_2b30 = { 7c 42 [2] 4e 60 [2] 48 55 [2] 66 55 [2] 59 49 }

  condition:
    any of them
}