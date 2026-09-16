rule TTP_XOR_WriteProcessMemory_09ee {
  strings:
    $key_09ee = { 5e 9c [2] 6c be [2] 6a 8b [2] 44 8b [2] 7b 97 }

  condition:
    any of them
}