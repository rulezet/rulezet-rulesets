rule TTP_XOR_WriteProcessMemory_62ee {
  strings:
    $key_62ee = { 35 9c [2] 07 be [2] 01 8b [2] 2f 8b [2] 10 97 }

  condition:
    any of them
}