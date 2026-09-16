rule TTP_XOR_WriteProcessMemory_52ee {
  strings:
    $key_52ee = { 05 9c [2] 37 be [2] 31 8b [2] 1f 8b [2] 20 97 }

  condition:
    any of them
}