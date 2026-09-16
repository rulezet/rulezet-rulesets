rule TTP_XOR_WriteProcessMemory_aced {
  strings:
    $key_aced = { fb 9f [2] c9 bd [2] cf 88 [2] e1 88 [2] de 94 }

  condition:
    any of them
}