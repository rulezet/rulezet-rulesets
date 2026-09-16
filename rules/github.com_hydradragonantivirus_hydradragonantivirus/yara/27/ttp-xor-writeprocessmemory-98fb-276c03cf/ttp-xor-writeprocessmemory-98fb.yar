rule TTP_XOR_WriteProcessMemory_98fb {
  strings:
    $key_98fb = { cf 89 [2] fd ab [2] fb 9e [2] d5 9e [2] ea 82 }

  condition:
    any of them
}