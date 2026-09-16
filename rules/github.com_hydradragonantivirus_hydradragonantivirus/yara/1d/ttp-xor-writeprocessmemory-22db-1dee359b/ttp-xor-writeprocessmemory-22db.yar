rule TTP_XOR_WriteProcessMemory_22db {
  strings:
    $key_22db = { 75 a9 [2] 47 8b [2] 41 be [2] 6f be [2] 50 a2 }

  condition:
    any of them
}