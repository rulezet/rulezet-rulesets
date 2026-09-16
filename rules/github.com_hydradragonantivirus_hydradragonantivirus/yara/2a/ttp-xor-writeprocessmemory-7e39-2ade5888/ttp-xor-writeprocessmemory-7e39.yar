rule TTP_XOR_WriteProcessMemory_7e39 {
  strings:
    $key_7e39 = { 29 4b [2] 1b 69 [2] 1d 5c [2] 33 5c [2] 0c 40 }

  condition:
    any of them
}