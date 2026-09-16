rule TTP_XOR_WriteProcessMemory_890f {
  strings:
    $key_890f = { de 7d [2] ec 5f [2] ea 6a [2] c4 6a [2] fb 76 }

  condition:
    any of them
}