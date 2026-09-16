rule TTP_XOR_WriteProcessMemory_893f {
  strings:
    $key_893f = { de 4d [2] ec 6f [2] ea 5a [2] c4 5a [2] fb 46 }

  condition:
    any of them
}