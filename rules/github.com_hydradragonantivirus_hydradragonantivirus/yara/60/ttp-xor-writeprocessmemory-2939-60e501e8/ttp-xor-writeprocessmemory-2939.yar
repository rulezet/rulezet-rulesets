rule TTP_XOR_WriteProcessMemory_2939 {
  strings:
    $key_2939 = { 7e 4b [2] 4c 69 [2] 4a 5c [2] 64 5c [2] 5b 40 }

  condition:
    any of them
}