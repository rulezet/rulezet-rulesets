rule TTP_XOR_WriteProcessMemory_8fcf {
  strings:
    $key_8fcf = { d8 bd [2] ea 9f [2] ec aa [2] c2 aa [2] fd b6 }

  condition:
    any of them
}