rule TTP_XOR_WriteProcessMemory_acea {
  strings:
    $key_acea = { fb 98 [2] c9 ba [2] cf 8f [2] e1 8f [2] de 93 }

  condition:
    any of them
}