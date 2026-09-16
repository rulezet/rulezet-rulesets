rule TTP_XOR_WriteProcessMemory_11ee {
  strings:
    $key_11ee = { 46 9c [2] 74 be [2] 72 8b [2] 5c 8b [2] 63 97 }

  condition:
    any of them
}