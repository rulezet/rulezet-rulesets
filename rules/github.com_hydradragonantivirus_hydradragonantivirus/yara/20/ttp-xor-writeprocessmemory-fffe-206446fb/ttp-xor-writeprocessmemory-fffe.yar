rule TTP_XOR_WriteProcessMemory_fffe {
  strings:
    $key_fffe = { a8 8c [2] 9a ae [2] 9c 9b [2] b2 9b [2] 8d 87 }

  condition:
    any of them
}