rule TTP_XOR_WriteProcessMemory_9ed9 {
  strings:
    $key_9ed9 = { c9 ab [2] fb 89 [2] fd bc [2] d3 bc [2] ec a0 }

  condition:
    any of them
}