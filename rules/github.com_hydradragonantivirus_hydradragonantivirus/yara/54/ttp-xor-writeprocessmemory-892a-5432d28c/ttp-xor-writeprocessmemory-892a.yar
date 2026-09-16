rule TTP_XOR_WriteProcessMemory_892a {
  strings:
    $key_892a = { de 58 [2] ec 7a [2] ea 4f [2] c4 4f [2] fb 53 }

  condition:
    any of them
}