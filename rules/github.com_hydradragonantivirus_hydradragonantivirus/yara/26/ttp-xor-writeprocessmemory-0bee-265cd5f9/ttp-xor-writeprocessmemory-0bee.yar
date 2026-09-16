rule TTP_XOR_WriteProcessMemory_0bee {
  strings:
    $key_0bee = { 5c 9c [2] 6e be [2] 68 8b [2] 46 8b [2] 79 97 }

  condition:
    any of them
}