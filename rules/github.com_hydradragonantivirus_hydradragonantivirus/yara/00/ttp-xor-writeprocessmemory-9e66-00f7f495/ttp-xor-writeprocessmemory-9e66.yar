rule TTP_XOR_WriteProcessMemory_9e66 {
  strings:
    $key_9e66 = { c9 14 [2] fb 36 [2] fd 03 [2] d3 03 [2] ec 1f }

  condition:
    any of them
}