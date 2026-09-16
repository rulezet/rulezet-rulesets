rule TTP_XOR_WriteProcessMemory_3e39 {
  strings:
    $key_3e39 = { 69 4b [2] 5b 69 [2] 5d 5c [2] 73 5c [2] 4c 40 }

  condition:
    any of them
}