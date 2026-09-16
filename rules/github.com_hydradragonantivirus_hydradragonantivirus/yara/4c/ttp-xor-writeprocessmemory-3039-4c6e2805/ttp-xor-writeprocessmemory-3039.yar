rule TTP_XOR_WriteProcessMemory_3039 {
  strings:
    $key_3039 = { 67 4b [2] 55 69 [2] 53 5c [2] 7d 5c [2] 42 40 }

  condition:
    any of them
}