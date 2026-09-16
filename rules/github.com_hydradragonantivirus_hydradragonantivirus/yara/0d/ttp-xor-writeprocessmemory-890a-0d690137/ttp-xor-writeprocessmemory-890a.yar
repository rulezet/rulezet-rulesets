rule TTP_XOR_WriteProcessMemory_890a {
  strings:
    $key_890a = { de 78 [2] ec 5a [2] ea 6f [2] c4 6f [2] fb 73 }

  condition:
    any of them
}