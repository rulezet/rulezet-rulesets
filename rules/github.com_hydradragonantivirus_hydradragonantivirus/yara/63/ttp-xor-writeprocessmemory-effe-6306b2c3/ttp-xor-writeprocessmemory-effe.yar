rule TTP_XOR_WriteProcessMemory_effe {
  strings:
    $key_effe = { b8 8c [2] 8a ae [2] 8c 9b [2] a2 9b [2] 9d 87 }

  condition:
    any of them
}