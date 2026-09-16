rule TTP_XOR_WriteProcessMemory_edbe {
  strings:
    $key_edbe = { ba cc [2] 88 ee [2] 8e db [2] a0 db [2] 9f c7 }

  condition:
    any of them
}