rule TTP_XOR_WriteProcessMemory_89de {
  strings:
    $key_89de = { de ac [2] ec 8e [2] ea bb [2] c4 bb [2] fb a7 }

  condition:
    any of them
}