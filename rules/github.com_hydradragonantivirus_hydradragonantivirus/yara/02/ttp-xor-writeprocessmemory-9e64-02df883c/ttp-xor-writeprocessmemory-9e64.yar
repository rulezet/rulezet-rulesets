rule TTP_XOR_WriteProcessMemory_9e64 {
  strings:
    $key_9e64 = { c9 16 [2] fb 34 [2] fd 01 [2] d3 01 [2] ec 1d }

  condition:
    any of them
}