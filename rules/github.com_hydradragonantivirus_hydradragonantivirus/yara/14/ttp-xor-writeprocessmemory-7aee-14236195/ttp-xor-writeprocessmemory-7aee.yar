rule TTP_XOR_WriteProcessMemory_7aee {
  strings:
    $key_7aee = { 2d 9c [2] 1f be [2] 19 8b [2] 37 8b [2] 08 97 }

  condition:
    any of them
}