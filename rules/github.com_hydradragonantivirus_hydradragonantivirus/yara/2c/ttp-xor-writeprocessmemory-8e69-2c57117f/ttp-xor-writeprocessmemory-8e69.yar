rule TTP_XOR_WriteProcessMemory_8e69 {
  strings:
    $key_8e69 = { d9 1b [2] eb 39 [2] ed 0c [2] c3 0c [2] fc 10 }

  condition:
    any of them
}