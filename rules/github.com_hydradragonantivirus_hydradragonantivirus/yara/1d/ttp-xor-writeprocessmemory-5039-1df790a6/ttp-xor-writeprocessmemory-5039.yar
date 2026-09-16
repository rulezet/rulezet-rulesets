rule TTP_XOR_WriteProcessMemory_5039 {
  strings:
    $key_5039 = { 07 4b [2] 35 69 [2] 33 5c [2] 1d 5c [2] 22 40 }

  condition:
    any of them
}