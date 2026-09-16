rule TTP_XOR_WriteProcessMemory_19ee {
  strings:
    $key_19ee = { 4e 9c [2] 7c be [2] 7a 8b [2] 54 8b [2] 6b 97 }

  condition:
    any of them
}