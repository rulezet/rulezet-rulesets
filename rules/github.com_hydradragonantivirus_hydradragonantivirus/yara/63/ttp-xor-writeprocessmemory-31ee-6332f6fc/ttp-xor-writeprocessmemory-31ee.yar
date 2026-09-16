rule TTP_XOR_WriteProcessMemory_31ee {
  strings:
    $key_31ee = { 66 9c [2] 54 be [2] 52 8b [2] 7c 8b [2] 43 97 }

  condition:
    any of them
}