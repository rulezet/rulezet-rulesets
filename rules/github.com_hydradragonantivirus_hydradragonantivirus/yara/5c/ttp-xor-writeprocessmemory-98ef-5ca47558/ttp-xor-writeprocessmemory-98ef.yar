rule TTP_XOR_WriteProcessMemory_98ef {
  strings:
    $key_98ef = { cf 9d [2] fd bf [2] fb 8a [2] d5 8a [2] ea 96 }

  condition:
    any of them
}