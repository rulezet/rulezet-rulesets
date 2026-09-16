rule TTP_XOR_WriteProcessMemory_42ee {
  strings:
    $key_42ee = { 15 9c [2] 27 be [2] 21 8b [2] 0f 8b [2] 30 97 }

  condition:
    any of them
}