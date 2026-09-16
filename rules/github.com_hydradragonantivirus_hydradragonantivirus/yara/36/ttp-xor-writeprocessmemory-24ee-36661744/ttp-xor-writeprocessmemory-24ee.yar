rule TTP_XOR_WriteProcessMemory_24ee {
  strings:
    $key_24ee = { 73 9c [2] 41 be [2] 47 8b [2] 69 8b [2] 56 97 }

  condition:
    any of them
}