rule TTP_XOR_WriteProcessMemory_4b39 {
  strings:
    $key_4b39 = { 1c 4b [2] 2e 69 [2] 28 5c [2] 06 5c [2] 39 40 }

  condition:
    any of them
}