rule TTP_XOR_WriteProcessMemory_acec {
  strings:
    $key_acec = { fb 9e [2] c9 bc [2] cf 89 [2] e1 89 [2] de 95 }

  condition:
    any of them
}