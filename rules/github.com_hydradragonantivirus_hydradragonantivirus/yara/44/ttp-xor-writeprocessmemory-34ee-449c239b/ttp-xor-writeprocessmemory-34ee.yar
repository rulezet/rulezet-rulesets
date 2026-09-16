rule TTP_XOR_WriteProcessMemory_34ee {
  strings:
    $key_34ee = { 63 9c [2] 51 be [2] 57 8b [2] 79 8b [2] 46 97 }

  condition:
    any of them
}