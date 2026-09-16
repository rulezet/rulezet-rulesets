rule TTP_XOR_WriteProcessMemory_9e16 {
  strings:
    $key_9e16 = { c9 64 [2] fb 46 [2] fd 73 [2] d3 73 [2] ec 6f }

  condition:
    any of them
}