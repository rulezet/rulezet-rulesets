rule TTP_XOR_WriteProcessMemory_61ee {
  strings:
    $key_61ee = { 36 9c [2] 04 be [2] 02 8b [2] 2c 8b [2] 13 97 }

  condition:
    any of them
}