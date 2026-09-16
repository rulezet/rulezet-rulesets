rule TTP_XOR_WriteProcessMemory_29ee {
  strings:
    $key_29ee = { 7e 9c [2] 4c be [2] 4a 8b [2] 64 8b [2] 5b 97 }

  condition:
    any of them
}