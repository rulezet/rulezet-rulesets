rule TTP_XOR_WriteProcessMemory_897d {
  strings:
    $key_897d = { de 0f [2] ec 2d [2] ea 18 [2] c4 18 [2] fb 04 }

  condition:
    any of them
}