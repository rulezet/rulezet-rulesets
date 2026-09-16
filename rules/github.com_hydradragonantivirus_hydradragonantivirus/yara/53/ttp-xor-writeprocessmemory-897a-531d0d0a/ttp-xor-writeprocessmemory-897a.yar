rule TTP_XOR_WriteProcessMemory_897a {
  strings:
    $key_897a = { de 08 [2] ec 2a [2] ea 1f [2] c4 1f [2] fb 03 }

  condition:
    any of them
}