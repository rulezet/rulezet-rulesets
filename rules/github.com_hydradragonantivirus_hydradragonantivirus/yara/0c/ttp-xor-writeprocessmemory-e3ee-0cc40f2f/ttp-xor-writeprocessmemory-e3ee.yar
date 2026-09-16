rule TTP_XOR_WriteProcessMemory_e3ee {
  strings:
    $key_e3ee = { b4 9c [2] 86 be [2] 80 8b [2] ae 8b [2] 91 97 }

  condition:
    any of them
}