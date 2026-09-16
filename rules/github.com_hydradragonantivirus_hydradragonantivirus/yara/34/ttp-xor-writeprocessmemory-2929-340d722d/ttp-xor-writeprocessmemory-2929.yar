rule TTP_XOR_WriteProcessMemory_2929 {
  strings:
    $key_2929 = { 7e 5b [2] 4c 79 [2] 4a 4c [2] 64 4c [2] 5b 50 }

  condition:
    any of them
}