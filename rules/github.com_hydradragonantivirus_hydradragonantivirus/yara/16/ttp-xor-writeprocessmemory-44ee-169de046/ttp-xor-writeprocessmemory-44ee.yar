rule TTP_XOR_WriteProcessMemory_44ee {
  strings:
    $key_44ee = { 13 9c [2] 21 be [2] 27 8b [2] 09 8b [2] 36 97 }

  condition:
    any of them
}