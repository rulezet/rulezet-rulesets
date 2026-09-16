rule TTP_XOR_WriteProcessMemory_3939 {
  strings:
    $key_3939 = { 6e 4b [2] 5c 69 [2] 5a 5c [2] 74 5c [2] 4b 40 }

  condition:
    any of them
}