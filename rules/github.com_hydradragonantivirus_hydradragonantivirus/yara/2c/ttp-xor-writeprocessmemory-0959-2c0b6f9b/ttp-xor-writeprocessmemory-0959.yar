rule TTP_XOR_WriteProcessMemory_0959 {
  strings:
    $key_0959 = { 5e 2b [2] 6c 09 [2] 6a 3c [2] 44 3c [2] 7b 20 }

  condition:
    any of them
}