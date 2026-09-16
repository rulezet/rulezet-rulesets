rule TTP_XOR_WriteProcessMemory_894f {
  strings:
    $key_894f = { de 3d [2] ec 1f [2] ea 2a [2] c4 2a [2] fb 36 }

  condition:
    any of them
}