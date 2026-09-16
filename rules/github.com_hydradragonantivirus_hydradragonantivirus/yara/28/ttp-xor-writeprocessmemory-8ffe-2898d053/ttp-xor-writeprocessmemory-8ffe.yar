rule TTP_XOR_WriteProcessMemory_8ffe {
  strings:
    $key_8ffe = { d8 8c [2] ea ae [2] ec 9b [2] c2 9b [2] fd 87 }

  condition:
    any of them
}