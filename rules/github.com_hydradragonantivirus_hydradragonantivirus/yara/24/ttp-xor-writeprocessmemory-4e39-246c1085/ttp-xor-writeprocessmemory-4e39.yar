rule TTP_XOR_WriteProcessMemory_4e39 {
  strings:
    $key_4e39 = { 19 4b [2] 2b 69 [2] 2d 5c [2] 03 5c [2] 3c 40 }

  condition:
    any of them
}