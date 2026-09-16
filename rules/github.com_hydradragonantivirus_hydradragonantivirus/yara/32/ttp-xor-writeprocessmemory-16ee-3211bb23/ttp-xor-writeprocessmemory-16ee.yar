rule TTP_XOR_WriteProcessMemory_16ee {
  strings:
    $key_16ee = { 41 9c [2] 73 be [2] 75 8b [2] 5b 8b [2] 64 97 }

  condition:
    any of them
}