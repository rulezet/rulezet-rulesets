rule TTP_XOR_WriteProcessMemory_edea {
  strings:
    $key_edea = { ba 98 [2] 88 ba [2] 8e 8f [2] a0 8f [2] 9f 93 }

  condition:
    any of them
}