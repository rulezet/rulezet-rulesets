rule TTP_XOR_WriteProcessMemory_6e39 {
  strings:
    $key_6e39 = { 39 4b [2] 0b 69 [2] 0d 5c [2] 23 5c [2] 1c 40 }

  condition:
    any of them
}