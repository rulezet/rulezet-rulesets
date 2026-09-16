rule TTP_XOR_WriteProcessMemory_89fa {
  strings:
    $key_89fa = { de 88 [2] ec aa [2] ea 9f [2] c4 9f [2] fb 83 }

  condition:
    any of them
}