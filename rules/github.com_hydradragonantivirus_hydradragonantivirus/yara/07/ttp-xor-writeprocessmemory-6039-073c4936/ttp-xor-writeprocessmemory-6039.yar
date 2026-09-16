rule TTP_XOR_WriteProcessMemory_6039 {
  strings:
    $key_6039 = { 37 4b [2] 05 69 [2] 03 5c [2] 2d 5c [2] 12 40 }

  condition:
    any of them
}