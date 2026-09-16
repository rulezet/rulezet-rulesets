rule TTP_XOR_WriteProcessMemory_eaee {
  strings:
    $key_eaee = { bd 9c [2] 8f be [2] 89 8b [2] a7 8b [2] 98 97 }

  condition:
    any of them
}