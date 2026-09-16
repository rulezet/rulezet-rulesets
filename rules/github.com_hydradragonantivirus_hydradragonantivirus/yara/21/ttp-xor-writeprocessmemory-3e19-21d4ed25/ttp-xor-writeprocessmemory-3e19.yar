rule TTP_XOR_WriteProcessMemory_3e19 {
  strings:
    $key_3e19 = { 69 6b [2] 5b 49 [2] 5d 7c [2] 73 7c [2] 4c 60 }

  condition:
    any of them
}