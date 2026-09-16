rule TTP_XOR_WriteProcessMemory_9871 {
  strings:
    $key_9871 = { cf 03 [2] fd 21 [2] fb 14 [2] d5 14 [2] ea 08 }

  condition:
    any of them
}