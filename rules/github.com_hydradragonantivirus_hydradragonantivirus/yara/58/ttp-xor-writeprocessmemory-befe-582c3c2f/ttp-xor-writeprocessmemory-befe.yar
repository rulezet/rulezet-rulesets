rule TTP_XOR_WriteProcessMemory_befe {
  strings:
    $key_befe = { e9 8c [2] db ae [2] dd 9b [2] f3 9b [2] cc 87 }

  condition:
    any of them
}